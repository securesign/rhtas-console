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
)

var (
	publicGoodInstance = "https://tuf-repo-cdn.sigstore.dev"
)

type TrustService interface {
	GetTrustConfig(ctx context.Context, tufRepoUrl string) (models.TrustConfig, error)
	GetTrustRootMetadataInfo(tufRepoUrl string) (models.RootMetadataInfoList, error)
	GetTarget(ctx context.Context, tufRepoUrl string, target string) (models.TargetContent, error)
	GetCertificatesInfo(ctx context.Context, tufRepoUrl string) (models.CertificateInfoList, error)
	GetAllTargets(ctx context.Context, tufRepoUrl string) (models.TargetsList, error)
}

// trustService manages TUF repository metadata
type trustService struct {
	repoLock        sync.RWMutex
	repo            *tufRepository
	repoReady       bool
	refreshInterval time.Duration
	tufRepoUrl      string
	db              *sql.DB
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

	s := &trustService{
		refreshInterval: refreshInterval,
		db:              db,
	}

	// Initialize database: run migrations
	if err := s.runMigrations(); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	// Perform initial targets population
	repo, err := s.getOrCreateUpdater(tufRepoUrl)
	if err != nil {
		log.Fatalf("failed to initialize default TUF repository %s: %v", tufRepoUrl, err)
	}
	ctx := context.Background()
	if err := s.populateTargets(ctx, repo); err != nil {
		log.Fatalf("failed to perform initial targets population for %s: %v", tufRepoUrl, err)
	}

	go s.runBackgroundRefresh()
	return s
}

func (s *trustService) GetTrustConfig(ctx context.Context, tufRepoUrl string) (models.TrustConfig, error) {
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
	}, nil
}

func (s *trustService) GetTrustRootMetadataInfo(tufRepoUrl string) (models.RootMetadataInfoList, error) {
	repo, err := s.getOrCreateUpdater(tufRepoUrl)
	if err != nil {
		return models.RootMetadataInfoList{}, err
	}

	repo.lock.RLock()
	defer repo.lock.RUnlock()

	// Fetch all root metadata versions
	latestRootMeta := repo.updater.GetTrustedMetadataSet().Root
	if latestRootMeta == nil {
		return models.RootMetadataInfoList{}, fmt.Errorf("latest root metadata not available")
	}

	latestVersion := latestRootMeta.Signed.Version
	var allRootBytes [][]byte
	latestRootBytes, err := latestRootMeta.ToBytes(true)
	if err != nil {
		return models.RootMetadataInfoList{}, fmt.Errorf("failed to get signed latest root bytes: %w", err)
	}
	allRootBytes = append(allRootBytes, latestRootBytes)

	// Fetch previous versions
	for version := 1; version < int(latestVersion); version++ {
		rootFilename := fmt.Sprintf("%d.root.json", version)
		metadataURL, err := url.JoinPath(repo.remoteMetadataURL, rootFilename)
		if err != nil {
			continue
		}
		resp, err := http.Get(metadataURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		rootBytes, err := io.ReadAll(resp.Body)
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
			return models.RootMetadataInfoList{}, fmt.Errorf("extracting root metadata info: %w", err)
		}
		results.Data = append(results.Data, rootInfo)
	}

	results.RepoUrl = &repo.opts.RepositoryBaseURL
	return results, nil
}

func (s *trustService) GetTarget(ctx context.Context, tufRepoUrl string, target string) (models.TargetContent, error) {
	// Get target content from database
	query := `
		SELECT content FROM targets WHERE target_name = ? AND repo_url = ?
	`
	row, err := s.db.QueryContext(ctx, query, target, tufRepoUrl)
	if err != nil {
		return models.TargetContent{}, fmt.Errorf("querying targets: %w", err)
	}
	defer row.Close()

	var content string
	row.Next()
	if err = row.Scan(&content); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.TargetContent{}, fmt.Errorf("no target found")
		}
		return models.TargetContent{}, fmt.Errorf("scanning target: %w", err)
	}

	return models.TargetContent{Content: content}, nil
}

func (s *trustService) GetCertificatesInfo(ctx context.Context, tufRepoUrl string) (models.CertificateInfoList, error) {
	// Get targets from database
	query := `
		SELECT target_name, type, status, content FROM targets WHERE repo_url = ?
	`
	rows, err := s.db.QueryContext(ctx, query, tufRepoUrl)
	if err != nil {
		return models.CertificateInfoList{}, fmt.Errorf("querying targets: %w", err)
	}
	defer rows.Close()
	targets := models.TargetsList{}
	for rows.Next() {
		var targetName, targetType, status, content string
		if err := rows.Scan(&targetName, &targetType, &status, &content); err != nil {
			return models.CertificateInfoList{}, fmt.Errorf("scanning target: %w", err)
		}
		targets.Data = append(targets.Data, models.TargetInfo{
			Name:    targetName,
			Type:    targetType,
			Status:  status,
			Content: content,
		})
	}
	result := models.CertificateInfoList{}

	for _, target := range targets.Data {
		// Only targets of type certificate
		if strings.ToLower(target.Type) == "fulcio" || strings.ToLower(target.Type) == "tsa" {
			if err != nil {
				return models.CertificateInfoList{}, fmt.Errorf("getting target certificate content: %w", err)
			}
			cert_info_list, err := extractCertDetails(target.Content)
			if err != nil {
				return models.CertificateInfoList{}, fmt.Errorf("extracting subject and issuer: %w", err)
			}
			for _, cert_info := range cert_info_list.Data {
				result.Data = append(result.Data, models.CertificateInfo{
					Issuer:     cert_info.Issuer,
					Subject:    cert_info.Subject,
					Expiration: cert_info.Expiration,
					Target:     target.Name,
					Status:     target.Status,
					Type:       target.Type,
					Pem:        cert_info.Pem,
				})
			}
		}
	}

	return result, nil
}

func (s *trustService) GetAllTargets(ctx context.Context, tufRepoUrl string) (models.TargetsList, error) {
	// Get targets from database
	query := `
		SELECT target_name, type, status, content FROM targets WHERE repo_url = ?
	`
	rows, err := s.db.QueryContext(ctx, query, tufRepoUrl)
	if err != nil {
		return models.TargetsList{}, fmt.Errorf("querying targets: %w", err)
	}
	defer rows.Close()

	result := models.TargetsList{}
	for rows.Next() {
		var targetName, targetType, status, content string
		if err := rows.Scan(&targetName, &targetType, &status, &content); err != nil {
			return models.TargetsList{}, fmt.Errorf("scanning target: %w", err)
		}
		result.Data = append(result.Data, models.TargetInfo{
			Name:    targetName,
			Type:    targetType,
			Status:  status,
			Content: content,
		})
	}
	return result, nil
}

// getOrCreateUpdater retrieves or initializes a TUF updater for the given repository URL.
func (s *trustService) getOrCreateUpdater(tufRepoUrl string) (*tufRepository, error) {
	s.repoLock.RLock()
	if s.repo != nil && s.tufRepoUrl == tufRepoUrl {
		if !s.repoReady {
			s.repoLock.RUnlock()
			return nil, fmt.Errorf("repository %s not yet initialized, try again later", tufRepoUrl)
		}
		repo := s.repo
		s.repoLock.RUnlock()
		return repo, nil
	}
	s.repoLock.RUnlock()

	s.repoLock.Lock()
	defer s.repoLock.Unlock()

	// Check to avoid race condition
	if s.repo != nil && s.tufRepoUrl == tufRepoUrl {
		if !s.repoReady {
			return nil, fmt.Errorf("repository %s not yet initialized, try again later", tufRepoUrl)
		}
		return s.repo, nil
	}

	// Initialize new TUF repository
	opts, err := buildTufOptions(tufRepoUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to build TUF options for %s: %w", tufRepoUrl, err)
	}
	tufCfg, err := buildTufConfig(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF config for %s: %w", tufRepoUrl, err)
	}

	up, err := updater.New(tufCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create updater for %s: %w", tufRepoUrl, err)
	}

	// Perform initial refresh
	if err := up.Refresh(); err != nil {
		return nil, fmt.Errorf("initial refresh failed for %s: %w", tufRepoUrl, err)
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
	return repo, nil
}

// runBackgroundRefresh periodically refreshes the TUF repository.
func (s *trustService) runBackgroundRefresh() {
	ticker := time.NewTicker(s.refreshInterval)
	defer ticker.Stop()

	for range ticker.C {
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
				return
			}
			newUpdater, err := updater.New(tufCfg)
			if err != nil {
				log.Printf("TUF: Failed to create new updater for %s: %v", url, err)
				return
			}
			if err := newUpdater.Refresh(); err != nil {
				log.Printf("TUF: Refresh failed for %s: %v", url, err)
				return
			}
			repo.updater = newUpdater
			repo.lastRefresh = time.Now().UTC()
			repo.lock.Unlock() // Release the write lock before calling populateTargets

			ctx := context.Background()
			if err := s.populateTargets(ctx, repo); err != nil {
				log.Printf("TUF: Failed to populate targets for %s: %v", url, err)
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

// buildTufOptions returns TUF options with the provided or default repository URL.
func buildTufOptions(tufRepoUrl string) (*tuf.Options, error) {
	opts := tuf.DefaultOptions()
	// if envRepoUrl := os.Getenv("TUF_REPO_URL"); envRepoUrl != "" {
	// 	opts.RepositoryBaseURL = envRepoUrl
	// } else if tufRepoUrl != "" {
	// 	opts.RepositoryBaseURL = tufRepoUrl
	// } else {
	// 	opts.RepositoryBaseURL = publicGoodInstance
	// }

	opts.RepositoryBaseURL = tufRepoUrl
	if !urlsEqual(opts.RepositoryBaseURL, publicGoodInstance) {
		if err := setOptsRoot(opts); err != nil {
			return nil, fmt.Errorf("failed to set root in options for %s: %w", tufRepoUrl, err)
		}
	}
	return opts, nil
}

// setOptsRoot fetches the root.json from the repository and sets it in the options.
func setOptsRoot(opts *tuf.Options) error {
	rootURL := opts.RepositoryBaseURL + "/root.json"
	resp, err := http.Get(rootURL)
	if err != nil {
		return fmt.Errorf("failed to fetch root.json: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch root.json: received status %d", resp.StatusCode)
	}

	rootData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read root.json: %w", err)
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
func (s *trustService) GetTargetFromTUFRepo(ctx context.Context, tufRepoUrl string, target string) (models.TargetContent, error) {
	repo, err := s.getOrCreateUpdater(tufRepoUrl)
	if err != nil {
		return models.TargetContent{}, err
	}

	repo.lock.RLock()
	defer repo.lock.RUnlock()

	// Check if context is cancelled
	if ctx.Err() != nil {
		return models.TargetContent{}, ctx.Err()
	}

	// Get Target content
	const filePath = ""
	ti, err := repo.updater.GetTargetInfo(target)
	if err != nil {
		return models.TargetContent{}, fmt.Errorf("getting info for target \"%s\": %w", target, err)
	}
	path, tb, err := repo.updater.FindCachedTarget(ti, filePath)
	if err != nil {
		return models.TargetContent{}, fmt.Errorf("getting target cache: %w", err)
	}
	if path != "" {
		// Cached version found
		return models.TargetContent{Content: string(tb)}, nil
	}

	// Download of target is needed
	// Ignore targetsBaseURL, set to empty string
	const targetsBaseURL = ""
	_, tb, err = repo.updater.DownloadTarget(ti, filePath, targetsBaseURL)
	if err != nil {
		return models.TargetContent{}, fmt.Errorf("failed to download target file %s: %w", target, err)
	}

	return models.TargetContent{Content: string(tb)}, nil
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
		return fmt.Errorf("querying database targets: %w", err)
	}
	defer rows.Close()

	// a given target exists (or not) in the DB
	dbTargets := make(map[string]bool)
	for rows.Next() {
		var targetName string
		if err := rows.Scan(&targetName); err != nil {
			return fmt.Errorf("scanning database targets: %w", err)
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

// populateTargets retrieves targets from the remote TUF repository and stores them in the database.
func (s *trustService) populateTargets(ctx context.Context, repo *tufRepository) error {
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

	for target, info := range targetMetadataSpecs {
		target_content, err := s.GetTargetFromTUFRepo(ctx, repo.remoteMetadataURL, target)
		if err != nil {
			return fmt.Errorf("failed to get content for target %s: %w", target, err)
		}
		targetInfo := models.TargetInfo{
			Name:    target,
			Type:    info["type"],
			Status:  info["status"],
			Content: target_content.Content,
		}
		if err := s.storeTarget(ctx, targetInfo, repo.remoteMetadataURL); err != nil {
			return fmt.Errorf("failed to store target %s: %w", target, err)
		}
	}
	return nil
}
