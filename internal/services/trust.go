package services

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/securesign/rhtas-console/internal/models"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

var (
	TufPublicGoodInstance = "https://tuf-repo-cdn.sigstore.dev"
)

type TrustService interface {
	GetTrustConfig(ctx context.Context, tufRepoUrl string) (cfg models.TrustConfig, statusCode int, err error)
	GetTrustRootMetadataInfo(ctx context.Context, tufRepoUrl string) (info models.RootMetadataInfoList, statusCode int, err error)
	GetTarget(ctx context.Context, tufRepoUrl string, target string) (content models.TargetContent, statusCode int, err error)
	GetCertificatesInfo(ctx context.Context, tufRepoUrl string) (certs models.CertificateInfoList, statusCode int, err error)
	GetAllTargets(ctx context.Context, tufRepoUrl string) (targets models.TargetsList, statusCode int, err error)
	CloseDB() error
}

// trustService manages TUF repository metadata
type trustService struct {
	repoLock        sync.RWMutex
	repo            *tufRepository
	repoReady       bool
	refreshInterval time.Duration
	tufRepoUrl      string
	db              *sql.DB
	ctx             context.Context
	cancel          context.CancelFunc
}

// tufRepository holds the TUF updater and associated metadata for a single repository
type tufRepository struct {
	updater           *updater.Updater
	opts              *tuf.Options
	lock              sync.RWMutex
	lastRefresh       time.Time
	refreshInProgress bool
	remoteMetadataURL string
}

type cachedTufRootResponse struct {
	body         []byte
	etag         string
	lastModified string
	expiresAt    time.Time
}

var (
	rootCache = struct {
		sync.RWMutex
		m map[string]*cachedTufRootResponse
	}{
		m: make(map[string]*cachedTufRootResponse),
	}

	rootFetchGroup singleflight.Group
)

func NewTrustService() TrustService {
	// Environment variables
	refreshInterval := 1 * time.Minute
	if envInterval := os.Getenv("TUF_REFRESH_INTERVAL"); envInterval != "" {
		if parsed, err := time.ParseDuration(envInterval); err == nil && parsed > 0 {
			refreshInterval = parsed
		}
	}

	// DB connection string
	// example: user:password@tcp(localhost:3306)/tuf_trust
	DB_DSN := os.Getenv("DB_DSN")
	if DB_DSN == "" {
		log.Fatal("DB_DSN env variable must be non-empty")
	}

	// TUF repository URL
	tufRepoUrl := os.Getenv("TUF_REPO_URL")
	if tufRepoUrl == "" {
		log.Fatal("TUF_REPO_URL env variable must be non-empty")
	}

	// Initialize MariaDB connection
	db, err := sql.Open("mysql", DB_DSN)
	if err != nil {
		log.Fatalf("failed to connect to MariaDB: %v", err)
	}
	if err = db.Ping(); err != nil {
		log.Fatalf("failed to ping MariaDB: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &trustService{
		refreshInterval: refreshInterval,
		db:              db,
		ctx:             ctx,
		cancel:          cancel,
	}

	// Initialize database: run migrations
	if err := s.runMigrations(); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	// Perform initial targets population
	repo, statusCode, err := s.getOrCreateUpdater(ctx, tufRepoUrl)
	if err != nil {
		log.Fatalf("failed to initialize default TUF repository %s (statusCode=%d): %v", tufRepoUrl, statusCode, err)
	}
	if _, err := s.populateTargets(ctx, repo); err != nil {
		log.Fatalf("failed to perform initial targets population for %s: %v", tufRepoUrl, err)
	}

	go s.runBackgroundRefresh()
	return s
}

func (s *trustService) GetTrustConfig(ctx context.Context, tufRepoUrl string) (models.TrustConfig, int, error) {
	// TODO: complete logic
	return models.TrustConfig{
		FulcioCertAuthorities: []struct {
			Pem     string `json:"pem"`
			Subject string `json:"subject"`
		}{
			{
				Pem:     "-----BEGIN CERTIFICATE-----\nstub-cert\n-----END CERTIFICATE-----",
				Subject: "stub-sub",
			},
		},
	}, http.StatusOK, nil
}

func (s *trustService) GetTrustRootMetadataInfo(ctx context.Context, tufRepoUrl string) (models.RootMetadataInfoList, int, error) {
	repo, statusCode, err := s.getOrCreateUpdater(ctx, tufRepoUrl)
	if err != nil {
		return models.RootMetadataInfoList{}, statusCode, err
	}

	repo.lock.RLock()
	defer repo.lock.RUnlock()

	// Fetch all root metadata versions
	latestRootMeta := repo.updater.GetTrustedMetadataSet().Root
	if latestRootMeta == nil {
		return models.RootMetadataInfoList{}, http.StatusServiceUnavailable, fmt.Errorf("latest root metadata not available")
	}

	latestVersion := latestRootMeta.Signed.Version
	var allRootBytes [][]byte
	latestRootBytes, err := latestRootMeta.ToBytes(true)
	if err != nil {
		return models.RootMetadataInfoList{}, http.StatusInternalServerError, fmt.Errorf("failed to get signed latest root bytes: %w", err)
	}
	allRootBytes = append(allRootBytes, latestRootBytes)

	// Fetch previous versions
	for version := 1; version < int(latestVersion); version++ {
		rootFilename := fmt.Sprintf("%d.root.json", version)
		metadataURL, err := url.JoinPath(repo.remoteMetadataURL, rootFilename)
		if err != nil {
			continue
		}

		rootBytes, err := fetchRootJSON(ctx, metadataURL)
		if err != nil {
			continue
		}
		var signedRoot data.Signed
		if err := json.Unmarshal(rootBytes, &signedRoot); err != nil {
			continue
		}
		allRootBytes = append(allRootBytes, rootBytes)
	}

	var results models.RootMetadataInfoList
	for _, rootBytes := range allRootBytes {
		rootInfo, err := extractRootMetadataInfo(rootBytes)
		if err != nil {
			return models.RootMetadataInfoList{}, http.StatusInternalServerError, fmt.Errorf("extracting root metadata info: %w", err)
		}
		results.Data = append(results.Data, rootInfo)
	}

	results.RepoUrl = &repo.opts.RepositoryBaseURL
	return results, http.StatusOK, nil
}

func (s *trustService) GetTarget(ctx context.Context, tufRepoUrl string, target string) (models.TargetContent, int, error) {
	// Get target content from database
	query := `
		SELECT content FROM targets WHERE target_name = ? AND repo_url = ?
	`
	row, err := s.db.QueryContext(ctx, query, target, tufRepoUrl)
	if err != nil {
		log.Printf("Failed to query DB (repo=%s, target=%s): %v", tufRepoUrl, target, err)
		return models.TargetContent{}, http.StatusInternalServerError, fmt.Errorf("could not query targets repository")
	}
	defer func() {
		if cerr := row.Close(); cerr != nil {
			log.Printf("failed to close rows: %v", cerr)
		}
	}()

	var content string
	row.Next()
	if err = row.Scan(&content); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Printf("No target found (repo=%s, target=%s): %v", tufRepoUrl, target, err)
			return models.TargetContent{}, http.StatusNotFound, fmt.Errorf("no target found")
		}
		log.Printf("Failed to scan target (repo=%s, target=%s): %v", tufRepoUrl, target, err)
		return models.TargetContent{}, http.StatusInternalServerError, fmt.Errorf("could not scan target")
	}

	return models.TargetContent{Content: content}, http.StatusOK, nil
}

func (s *trustService) GetCertificatesInfo(ctx context.Context, tufRepoUrl string) (models.CertificateInfoList, int, error) {
	// Get targets from database
	query := `
		SELECT target_name, type, status, content FROM targets WHERE repo_url = ?
	`
	rows, err := s.db.QueryContext(ctx, query, tufRepoUrl)
	if err != nil {
		log.Printf("Failed to query DB (repo=%s): %v", tufRepoUrl, err)
		return models.CertificateInfoList{}, http.StatusInternalServerError, fmt.Errorf("could not query targets repository")
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.Printf("failed to close rows: %v", cerr)
		}
	}()

	result := models.CertificateInfoList{}
	for rows.Next() {
		var targetName, targetType, status, content string
		if err := rows.Scan(&targetName, &targetType, &status, &content); err != nil {
			log.Printf("Failed to scan target (repo=%s, target=%s): %v", tufRepoUrl, targetName, err)
			return models.CertificateInfoList{}, http.StatusInternalServerError, fmt.Errorf("could not scan target")
		}

		// Only certificate-related targets
		switch strings.ToLower(targetType) {
		case "fulcio", "tsa":
			certInfoList, err := extractCertDetails(content)
			if err != nil {
				log.Printf("Failed to get target certificate content (repo=%s, target=%s): %v", tufRepoUrl, targetName, err)
				return models.CertificateInfoList{}, http.StatusInternalServerError, fmt.Errorf("could not get target certificate content")
			}
			for _, cert_info := range certInfoList.Data {
				result.Data = append(result.Data, models.CertificateInfo{
					Issuer:     cert_info.Issuer,
					Subject:    cert_info.Subject,
					Expiration: cert_info.Expiration,
					Target:     targetName,
					Status:     status,
					Type:       targetType,
					Pem:        cert_info.Pem,
				})
			}
		}
	}

	if err := rows.Err(); err != nil {
		log.Printf("Row iteration error (repo=%s): %v", tufRepoUrl, err)
		return models.CertificateInfoList{}, http.StatusInternalServerError, fmt.Errorf("row iteration failed")
	}

	return result, http.StatusOK, nil
}

func (s *trustService) GetAllTargets(ctx context.Context, tufRepoUrl string) (models.TargetsList, int, error) {
	// Get targets from database
	query := `
		SELECT target_name, type, status, content FROM targets WHERE repo_url = ?
	`
	rows, err := s.db.QueryContext(ctx, query, tufRepoUrl)
	if err != nil {
		log.Printf("Failed to query DB (repo=%s): %v", tufRepoUrl, err)
		return models.TargetsList{}, http.StatusInternalServerError, fmt.Errorf("could not query targets")
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.Printf("failed to close rows: %v", cerr)
		}
	}()

	result := models.TargetsList{}
	for rows.Next() {
		var targetName, targetType, status, content string
		if err := rows.Scan(&targetName, &targetType, &status, &content); err != nil {
			log.Printf("Failed to scan target (repo=%s, target=%s): %v", tufRepoUrl, targetName, err)
			return models.TargetsList{}, http.StatusInternalServerError, fmt.Errorf("could not scan target")
		}
		result.Data = append(result.Data, models.TargetInfo{
			Name:    targetName,
			Type:    targetType,
			Status:  status,
			Content: content,
		})
	}
	return result, http.StatusOK, nil
}

// getOrCreateUpdater retrieves or initializes a TUF updater for the given repository URL.
func (s *trustService) getOrCreateUpdater(ctx context.Context, tufRepoUrl string) (*tufRepository, int, error) {
	s.repoLock.RLock()
	if s.repo != nil && s.tufRepoUrl == tufRepoUrl {
		if !s.repoReady {
			s.repoLock.RUnlock()
			return nil, http.StatusServiceUnavailable, fmt.Errorf("repository %s not yet initialized, try again later", tufRepoUrl)
		}
		repo := s.repo
		s.repoLock.RUnlock()
		return repo, http.StatusOK, nil
	}
	s.repoLock.RUnlock()

	s.repoLock.Lock()
	defer s.repoLock.Unlock()

	// Check to avoid race condition
	if s.repo != nil && s.tufRepoUrl == tufRepoUrl {
		if !s.repoReady {
			return nil, http.StatusServiceUnavailable, fmt.Errorf("repository %s not yet initialized, try again later", tufRepoUrl)
		}
		return s.repo, http.StatusOK, nil
	}

	// Initialize new TUF repository
	opts, err := buildTufOptions(ctx, tufRepoUrl)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to build TUF options for %s: %w", tufRepoUrl, err)
	}
	tufCfg, err := buildTufConfig(opts)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to create TUF config for %s: %w", tufRepoUrl, err)
	}

	up, err := updater.New(tufCfg)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to create updater for %s: %w", tufRepoUrl, err)
	}

	// Perform initial refresh
	if err := up.Refresh(); err != nil {
		return nil, http.StatusServiceUnavailable, fmt.Errorf("initial refresh failed for %s: %w", tufRepoUrl, err)
	}

	repo := &tufRepository{
		updater:           up,
		opts:              opts,
		lastRefresh:       time.Now().UTC(),
		remoteMetadataURL: tufCfg.RemoteMetadataURL,
	}
	s.repo = repo
	s.tufRepoUrl = s.repo.remoteMetadataURL
	s.repoReady = true
	return repo, http.StatusOK, nil
}

// runBackgroundRefresh periodically refreshes the TUF repository.
func (s *trustService) runBackgroundRefresh() {
	ticker := time.NewTicker(s.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			log.Println("Stopping background refresh")
			return
		case <-ticker.C:
			s.repoLock.RLock()
			repo := s.repo
			url := s.tufRepoUrl
			s.repoLock.RUnlock()

			if repo == nil {
				continue
			}

			repo.lock.Lock()
			if repo.refreshInProgress {
				log.Printf("TUF: Refresh already in progress for %s, skipping", url)
				repo.lock.Unlock()
				continue
			}
			repo.refreshInProgress = true
			repo.lock.Unlock()

			// Perform refresh in a separate goroutine
			go func(repo *tufRepository, url string) {
				repo.lock.Lock()
				defer func() { repo.refreshInProgress = false }()

				// Create a new updater for each refresh cycle
				tufCfg, err := buildTufConfig(repo.opts)
				if err != nil {
					log.Printf("TUF: Failed to create TUF config for %s: %v", url, err)
					repo.lock.Unlock()
					return
				}
				newUpdater, err := updater.New(tufCfg)
				if err != nil {
					log.Printf("TUF: Failed to create new updater for %s: %v", url, err)
					repo.lock.Unlock()
					return
				}
				if err := newUpdater.Refresh(); err != nil {
					log.Printf("TUF: Refresh failed for %s: %v", url, err)
					repo.lock.Unlock()
					return
				}
				repo.updater = newUpdater
				repo.lastRefresh = time.Now().UTC()
				repo.lock.Unlock() // Release the write lock before calling populateTargets

				ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
				defer cancel()
				if statusCode, err := s.populateTargets(ctx, repo); err != nil {
					log.Printf("TUF: Failed to populate targets for %s (statusCode=%d): %v", url, statusCode, err)
					return
				}
				if err := s.syncDatabaseWithTargets(repo); err != nil {
					log.Printf("TUF: Failed to sync database for %s: %v", url, err)
					return
				}
				log.Printf("TUF: Successfully refreshed repository %s", url)
			}(repo, url)
		}
	}
}

// CloseDB cancels the periodic refreshes and closes the db connection
func (s *trustService) CloseDB() error {
	s.cancel() // Stop the background refresh
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// buildTufOptions returns TUF options with the provided or default repository URL.
func buildTufOptions(ctx context.Context, tufRepoUrl string) (*tuf.Options, error) {
	opts := tuf.DefaultOptions()
	opts.RepositoryBaseURL = tufRepoUrl
	if !urlsEqual(opts.RepositoryBaseURL, TufPublicGoodInstance) {
		if err := setOptsRoot(ctx, opts); err != nil {
			return nil, fmt.Errorf("failed to set root in options for %s: %w", tufRepoUrl, err)
		}
	}
	return opts, nil
}

const rootTTL = 30 * time.Minute

// fetchRootJSON returns root.json using an in-memory cache with TTL and conditional HTTP requests.
func fetchRootJSON(ctx context.Context, url string) ([]byte, error) {
	// Fast path: fresh cache
	rootCache.RLock()
	if entry, ok := rootCache.m[url]; ok && time.Now().Before(entry.expiresAt) {
		defer rootCache.RUnlock()
		return entry.body, nil
	}
	rootCache.RUnlock()

	// Slow path: deduplicated fetch
	val, err, _ := rootFetchGroup.Do(url, func() (any, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		// Attach conditional headers if present
		rootCache.RLock()
		if entry, ok := rootCache.m[url]; ok {
			if entry.etag != "" {
				req.Header.Set("If-None-Match", entry.etag)
			}
			if entry.lastModified != "" {
				req.Header.Set("If-Modified-Since", entry.lastModified)
			}
		}
		rootCache.RUnlock()

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				log.Println("failed to close response body:", err)
			}
		}()

		switch resp.StatusCode {
		case http.StatusNotModified:
			// Reuse cached body, just bump TTL
			rootCache.Lock()
			entry := rootCache.m[url]
			entry.expiresAt = time.Now().Add(rootTTL)
			body := entry.body
			rootCache.Unlock()
			return body, nil

		case http.StatusOK:
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}

			rootCache.Lock()
			rootCache.m[url] = &cachedTufRootResponse{
				body:         body,
				etag:         resp.Header.Get("ETag"),
				lastModified: resp.Header.Get("Last-Modified"),
				expiresAt:    time.Now().Add(rootTTL),
			}
			rootCache.Unlock()

			return body, nil

		default:
			return nil, fmt.Errorf("unexpected status %d fetching root.json", resp.StatusCode)
		}
	})

	if err != nil {
		return nil, err
	}
	return val.([]byte), nil
}

// setOptsRoot fetches root.json (from cache or network) and stores it in TUF options.
func setOptsRoot(ctx context.Context, opts *tuf.Options) error {
	rootURL := opts.RepositoryBaseURL + "/root.json"
	rootData, err := fetchRootJSON(ctx, rootURL)
	if err != nil {
		return fmt.Errorf("failed to fetch root.json: %w", err)
	}
	opts.Root = rootData
	return nil
}

// buildTufConfig creates a TUF updater config based on the given options.
func buildTufConfig(opts *tuf.Options) (*config.UpdaterConfig, error) {
	tufCfg, err := config.New(opts.RepositoryBaseURL, opts.Root)
	if err != nil {
		return nil, fmt.Errorf("failed to create config: %w", err)
	}

	tufCfg.LocalMetadataDir = filepath.Join(opts.CachePath, tuf.URLToPath(opts.RepositoryBaseURL))
	tufCfg.LocalTargetsDir = filepath.Join(tufCfg.LocalMetadataDir, "targets")
	tufCfg.DisableLocalCache = opts.DisableLocalCache
	tufCfg.PrefixTargetsWithHash = !opts.DisableConsistentSnapshot

	if opts.Fetcher != nil {
		tufCfg.Fetcher = opts.Fetcher
	} else {
		f := fetcher.NewDefaultFetcher()
		f.SetHTTPUserAgent(util.ConstructUserAgent())
		tufCfg.Fetcher = f
	}

	return tufCfg, nil
}

// extractRootMetadataInfo retrieves TUF root metadata info including version, expiration, and status.
func extractRootMetadataInfo(rootMetadataBytes []byte) (models.RootMetadataInfo, error) {
	var parsed struct {
		Signed struct {
			Expired string `json:"expires"`
			Version int    `json:"version"`
		} `json:"signed"`
	}

	if err := json.Unmarshal(rootMetadataBytes, &parsed); err != nil {
		return models.RootMetadataInfo{}, fmt.Errorf("unmarshal root metadata: %w", err)
	}

	expiresTime, err := time.Parse(time.RFC3339, parsed.Signed.Expired)
	if err != nil {
		return models.RootMetadataInfo{}, fmt.Errorf("parse expires time: %w", err)
	}

	now := time.Now().UTC()
	var status string

	switch {
	case expiresTime.Before(now):
		status = "expired"
	case expiresTime.Sub(now) < 30*24*time.Hour:
		status = "expiring"
	default:
		status = "valid"
	}

	rootMetadataInfo := models.RootMetadataInfo{
		Version: strconv.Itoa(parsed.Signed.Version),
		Expires: parsed.Signed.Expired,
		Status:  status,
	}

	return rootMetadataInfo, nil
}

// extractTargetMetadataInfo extracts status & usage of targets
func extractTargetMetadataInfo(targetsBytes []byte) (map[string]map[string]string, error) {
	var parsed struct {
		Signed struct {
			Targets map[string]struct {
				Custom struct {
					Sigstore struct {
						Status string `json:"status"`
						Usage  string `json:"usage"`
					} `json:"sigstore"`
				} `json:"custom"`
			} `json:"targets"`
		} `json:"signed"`
	}

	if err := json.Unmarshal(targetsBytes, &parsed); err != nil {
		return nil, fmt.Errorf("unmarshal targets metadata: %w", err)
	}

	targetSpecs := make(map[string]map[string]string)
	for name, target := range parsed.Signed.Targets {
		targetSpecs[name] = map[string]string{
			"status": target.Custom.Sigstore.Status,
			"type":   target.Custom.Sigstore.Usage,
		}
	}

	return targetSpecs, nil
}

// extractCertDetails extracts subject, issuer & status from a PEM certificate
func extractCertDetails(certPEM string) (models.CertificateInfoList, error) {
	var results models.CertificateInfoList
	rest := []byte(certPEM)
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining

		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return models.CertificateInfoList{}, fmt.Errorf("failed to parse certificate: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		entry := models.CertificateInfo{
			Subject:    cert.Subject.String(),
			Issuer:     cert.Issuer.String(),
			Expiration: cert.NotAfter.String(),
			Pem:        string(pemBytes),
		}
		results.Data = append(results.Data, entry)
	}

	if len(results.Data) == 0 {
		return models.CertificateInfoList{}, fmt.Errorf("no valid certificates found")
	}
	return results, nil
}

// urlsEqual compares two URLs for logical equivalence, ignoring trailing slashes.
func urlsEqual(a, b string) bool {
	ua, err1 := url.Parse(strings.TrimRight(a, "/"))
	ub, err2 := url.Parse(strings.TrimRight(b, "/"))
	return err1 == nil && err2 == nil && ua.String() == ub.String()
}

// GetTarget retrieves the target content from the remote TUF repository
func (s *trustService) GetTargetFromTUFRepo(ctx context.Context, tufRepoUrl string, target string) (models.TargetContent, int, error) {
	repo, statusCode, err := s.getOrCreateUpdater(ctx, tufRepoUrl)
	if err != nil {
		return models.TargetContent{}, statusCode, err
	}

	repo.lock.RLock()
	defer repo.lock.RUnlock()

	// Check if context is cancelled
	if err := ctx.Err(); err != nil {
		var statusCode int
		switch {
		case errors.Is(err, context.Canceled):
			statusCode = 499
		case errors.Is(err, context.DeadlineExceeded):
			statusCode = http.StatusGatewayTimeout
		default:
			statusCode = http.StatusInternalServerError
		}
		return models.TargetContent{}, statusCode, err
	}

	// Get Target content
	const filePath = ""
	ti, err := repo.updater.GetTargetInfo(target)
	if err != nil {
		return models.TargetContent{}, http.StatusInternalServerError, fmt.Errorf("getting info for target \"%s\": %w", target, err)
	}
	path, tb, err := repo.updater.FindCachedTarget(ti, filePath)
	if err != nil {
		return models.TargetContent{}, http.StatusInternalServerError, fmt.Errorf("getting target cache: %w", err)
	}
	if path != "" {
		// Cached version found
		return models.TargetContent{Content: string(tb)}, http.StatusOK, nil
	}

	// Download of target is needed
	// Ignore targetsBaseURL, set to empty string
	const targetsBaseURL = ""
	_, tb, err = repo.updater.DownloadTarget(ti, filePath, targetsBaseURL)
	if err != nil {
		return models.TargetContent{}, http.StatusInternalServerError, fmt.Errorf("failed to download target file %s: %w", target, err)
	}

	return models.TargetContent{Content: string(tb)}, http.StatusOK, nil
}

// syncDatabaseWithTargets updates the database to reflect the current targets from the remote TUF repository.
func (s *trustService) syncDatabaseWithTargets(repo *tufRepository) error {
	// Get targets from remote repository
	targetsMeta := repo.updater.GetTrustedMetadataSet().Targets["targets"]
	if targetsMeta == nil {
		return fmt.Errorf("targets metadata not available")
	}
	targetsBytes, err := targetsMeta.ToBytes(true)
	if err != nil {
		return fmt.Errorf("failed to get targets bytes: %w", err)
	}
	targetMetadataSpecs, err := extractTargetMetadataInfo(targetsBytes)
	if err != nil {
		return fmt.Errorf("extracting target metadata: %w", err)
	}

	// Get current targets in database (excluding already revoked)
	rows, err := s.db.Query("SELECT target_name FROM targets WHERE repo_url = ? AND status IN ('Active', 'Expired')", repo.remoteMetadataURL)
	if err != nil {
		log.Printf("Failed to query database targets (repo=%s): %v", repo.remoteMetadataURL, err)
		return fmt.Errorf("could not query database targets")
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.Printf("failed to close rows: %v", cerr)
		}
	}()

	// a given target exists (or not) in the DB
	dbTargets := make(map[string]bool)
	for rows.Next() {
		var targetName string
		if err := rows.Scan(&targetName); err != nil {
			log.Printf("Failed to scan database targets (repo=%s): %v", repo.remoteMetadataURL, err)
			return fmt.Errorf("scanning database targets")
		}
		dbTargets[targetName] = true
	}

	// Mark removed targets as revoked
	for target := range dbTargets {
		if _, exists := targetMetadataSpecs[target]; !exists {
			_, err := s.db.Exec("UPDATE targets SET status = 'Revoked', updated_at = NOW() WHERE repo_url = ? AND target_name = ?", repo.remoteMetadataURL, target)
			if err != nil {
				log.Printf("failed to mark target %s as Revoked: %v", target, err)
			}
		}
	}
	return nil
}

// runMigrations applies database migrations using golang-migrate
func (s *trustService) runMigrations() error {
	driver, err := mysql.WithInstance(s.db, &mysql.Config{})
	if err != nil {
		return fmt.Errorf("failed to initialize migration driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://internal/db/migrations",
		"mysql",
		driver,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize migrations: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	return nil
}

// storeTarget inserts or updates a target's metadata and content in the database.
func (s *trustService) storeTarget(ctx context.Context, target models.TargetInfo, repoUrl string) error {
	query := `
		INSERT INTO targets (
			repo_url, target_name, type, status, content, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, NOW(), NOW())
		ON DUPLICATE KEY UPDATE
			type = VALUES(type),
			status = VALUES(status),
			content = VALUES(content),
			updated_at = NOW()
	`
	status := target.Status
	// It happens when "status": ""
	if status != "Active" && status != "Expired" {
		status = "Active"
	}
	_, err := s.db.ExecContext(ctx, query, repoUrl, target.Name, target.Type, status, target.Content)
	return err
}

// maxTargetFetchConcurrency limits the number of concurrent target fetch operations.
const maxTargetFetchConcurrency = 5

// targetFetchError wraps an error with the corresponding HTTP status code.
type targetFetchError struct {
	status int
	err    error
}

func (e *targetFetchError) Error() string {
	return e.err.Error()
}

func (e *targetFetchError) Unwrap() error {
	return e.err
}

// populateTargets retrieves targets from the remote TUF repository and stores them in the database.
func (s *trustService) populateTargets(ctx context.Context, repo *tufRepository) (int, error) {
	targetsMeta := repo.updater.GetTrustedMetadataSet().Targets["targets"]
	if targetsMeta == nil {
		return http.StatusServiceUnavailable, fmt.Errorf("targets metadata not available")
	}
	targetsBytes, err := targetsMeta.ToBytes(true)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to get targets bytes: %w", err)
	}
	targetMetadataSpecs, err := extractTargetMetadataInfo(targetsBytes)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("extracting target metadata: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxTargetFetchConcurrency)

	for target, info := range targetMetadataSpecs {
		target := target
		info := info

		g.Go(func() error {
			target_content, statusCode, err := s.GetTargetFromTUFRepo(ctx, repo.remoteMetadataURL, target)
			if err != nil {
				return &targetFetchError{
					status: statusCode,
					err:    fmt.Errorf("failed to get content for target %s: %w", target, err),
				}
			}
			targetInfo := models.TargetInfo{
				Name:    target,
				Type:    info["type"],
				Status:  info["status"],
				Content: target_content.Content,
			}
			if err := s.storeTarget(ctx, targetInfo, repo.remoteMetadataURL); err != nil {
				log.Printf("Failed to store target (repo=%s, target=%s): %v", repo.remoteMetadataURL, target, err)
				return &targetFetchError{
					status: http.StatusInternalServerError,
					err:    fmt.Errorf("failed to store target %s: %w", target, err),
				}
			}
			return nil
		})

	}
	if err := g.Wait(); err != nil {
		var tfErr *targetFetchError
		if errors.As(err, &tfErr) {
			return tfErr.status, tfErr.err
		}

		// Fallback for unexpected errors
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}
