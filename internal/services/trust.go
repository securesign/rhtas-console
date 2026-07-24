package services

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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

	"github.com/securesign/rhtas-console/internal/models"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
	"golang.org/x/sync/singleflight"
)

var (
	TufPublicGoodInstance = "https://tuf-repo-cdn.sigstore.dev"
)

// TrustServiceFlags holds all configuration from command-line flags
type TrustServiceFlags struct {
	TUFRepoURL      string
	RefreshInterval time.Duration
}

type TrustService interface {
	GetTrustConfig(ctx context.Context, tufRepoUrl string) (cfg models.TrustConfig, statusCode int, err error)
	GetTrustMetadataInfo(ctx context.Context, tufRepoUrl string) (info models.MetadataInfoResponse, statusCode int, err error)
	GetTarget(ctx context.Context, tufRepoUrl string, target string) (content models.TargetContent, statusCode int, err error)
	GetCertificatesInfo(ctx context.Context, tufRepoUrl string) (certs models.CertificateInfoList, statusCode int, err error)
	GetAllTargets(ctx context.Context, tufRepoUrl string) (targets models.TargetsList, statusCode int, err error)
	GetTrustCoverage(ctx context.Context, timeWindow string, environment *string, tufRepoUrl string) (coverage models.TrustCoverageResponse, statusCode int, err error)
	GetTUFRepoURL() string
	Close() error
}

// trustService manages TUF repository metadata
type trustService struct {
	repoLock        sync.RWMutex
	repo            *tufRepository
	repoReady       bool
	refreshInterval time.Duration

	validForMu      sync.RWMutex
	validForCache   map[string]validForWindow
	validForExpiry  time.Time
	validForRepoUrl string
	validForFlight  singleflight.Group
	tufRepoUrl      string
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

func NewTrustService(flags *TrustServiceFlags) TrustService {
	if flags == nil {
		log.Fatal("TrustServiceFlags are required")
	}

	if flags.TUFRepoURL == "" {
		log.Fatal("--tuf-repo-url flag must be non-empty")
	}

	refreshInterval := flags.RefreshInterval
	if refreshInterval <= 0 {
		refreshInterval = 1 * time.Minute
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &trustService{
		refreshInterval: refreshInterval,
		ctx:             ctx,
		cancel:          cancel,
	}

	// Initialize TUF repository
	repo, statusCode, err := s.getOrCreateUpdater(ctx, flags.TUFRepoURL)
	if err != nil {
		log.Fatalf("failed to initialize TUF repository %s (statusCode=%d): %v", flags.TUFRepoURL, statusCode, err)
	}

	// Acquire lock before setting repo fields to prevent race conditions
	s.repoLock.Lock()
	s.repo = repo
	s.tufRepoUrl = repo.remoteMetadataURL
	s.repoReady = true
	s.repoLock.Unlock()

	// Pre-fetch all targets in parallel to improve first-request latency
	go s.preFetchAllTargets(ctx, repo)

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

func (s *trustService) GetTrustMetadataInfo(ctx context.Context, tufRepoUrl string) (models.MetadataInfoResponse, int, error) {
	repo, statusCode, err := s.getOrCreateUpdater(ctx, tufRepoUrl)
	if err != nil {
		return models.MetadataInfoResponse{}, statusCode, err
	}

	repo.lock.RLock()
	defer repo.lock.RUnlock()

	trustedMeta := repo.updater.GetTrustedMetadataSet()

	// Root: fetch all historical versions
	if trustedMeta.Root == nil {
		return models.MetadataInfoResponse{}, http.StatusServiceUnavailable, fmt.Errorf("root metadata not available")
	}

	latestVersion := trustedMeta.Root.Signed.Version
	var allRootBytes [][]byte
	latestRootBytes, err := trustedMeta.Root.ToBytes(true)
	if err != nil {
		return models.MetadataInfoResponse{}, http.StatusInternalServerError, fmt.Errorf("failed to get signed latest root bytes: %w", err)
	}
	allRootBytes = append(allRootBytes, latestRootBytes)

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

	var rootEntries []models.MetadataInfo
	for _, rootBytes := range allRootBytes {
		rootInfo, err := extractRootMetadataInfo(rootBytes)
		if err != nil {
			return models.MetadataInfoResponse{}, http.StatusInternalServerError, fmt.Errorf("extracting root metadata info: %w", err)
		}
		rootEntries = append(rootEntries, rootInfo)
	}

	result := models.MetadataInfoResponse{
		Data:    map[string][]models.MetadataInfo{"root": rootEntries},
		RepoUrl: &repo.opts.RepositoryBaseURL,
	}

	if targets := trustedMeta.Targets["targets"]; targets != nil {
		result.Data["targets"] = []models.MetadataInfo{
			metadataInfoFromVersionAndExpires(targets.Signed.Version, targets.Signed.Expires),
		}
	}

	if trustedMeta.Snapshot != nil {
		result.Data["snapshot"] = []models.MetadataInfo{
			metadataInfoFromVersionAndExpires(trustedMeta.Snapshot.Signed.Version, trustedMeta.Snapshot.Signed.Expires),
		}
	}

	if trustedMeta.Timestamp != nil {
		result.Data["timestamp"] = []models.MetadataInfo{
			metadataInfoFromVersionAndExpires(trustedMeta.Timestamp.Signed.Version, trustedMeta.Timestamp.Signed.Expires),
		}
	}

	return result, http.StatusOK, nil
}

func (s *trustService) GetTarget(ctx context.Context, tufRepoUrl string, target string) (models.TargetContent, int, error) {
	// Get target content directly from TUF cache
	return s.GetTargetFromTUFRepo(ctx, tufRepoUrl, target)
}

func (s *trustService) GetCertificatesInfo(ctx context.Context, tufRepoUrl string) (models.CertificateInfoList, int, error) {
	// Get targets directly from TUF metadata
	s.repoLock.RLock()
	repo := s.repo
	repoReady := s.repoReady
	s.repoLock.RUnlock()

	if !repoReady || repo == nil {
		return models.CertificateInfoList{}, http.StatusServiceUnavailable, fmt.Errorf("TUF repository not ready")
	}

	// Acquire repo.lock to safely access repo.updater
	repo.lock.RLock()
	targetsMeta := repo.updater.GetTrustedMetadataSet().Targets["targets"]
	if targetsMeta == nil {
		repo.lock.RUnlock()
		return models.CertificateInfoList{}, http.StatusInternalServerError, fmt.Errorf("targets metadata not available")
	}

	targetsBytes, err := targetsMeta.ToBytes(true)
	repo.lock.RUnlock()

	if err != nil {
		return models.CertificateInfoList{}, http.StatusInternalServerError, fmt.Errorf("failed to get targets bytes: %w", err)
	}

	targetMetadataSpecs, err := extractTargetMetadataInfo(targetsBytes)
	if err != nil {
		return models.CertificateInfoList{}, http.StatusInternalServerError, fmt.Errorf("extracting target metadata: %w", err)
	}

	validForLookup := s.getValidForLookup(ctx, tufRepoUrl)

	result := models.CertificateInfoList{}
	var fetchErrors []string

	for targetName, spec := range targetMetadataSpecs {
		// Only certificate-related targets
		targetType := spec["type"]
		switch strings.ToLower(targetType) {
		case "fulcio", "tsa":
			// Fetch target content from TUF cache
			targetContent, statusCode, err := s.GetTargetFromTUFRepo(ctx, tufRepoUrl, targetName)
			if err != nil {
				errMsg := fmt.Sprintf("failed to get target %s: %v", targetName, err)
				log.Print(errMsg)
				fetchErrors = append(fetchErrors, errMsg)
				continue
			}
			if statusCode != http.StatusOK {
				errMsg := fmt.Sprintf("failed to get target %s: status code %d", targetName, statusCode)
				log.Print(errMsg)
				fetchErrors = append(fetchErrors, errMsg)
				continue
			}

			parsedCerts, err := extractCertDetails(targetContent.Content)
			if err != nil {
				errMsg := fmt.Sprintf("failed to extract certificate details from target %s: %v", targetName, err)
				log.Print(errMsg)
				fetchErrors = append(fetchErrors, errMsg)
				continue
			}

			now := time.Now()
			for _, pc := range parsedCerts {
				var vfPtr *validForWindow
				if vf, ok := validForLookup[pc.fingerprint]; ok {
					vfPtr = &vf
				}

				info := models.CertificateInfo{
					Issuer:         pc.info.Issuer,
					Subject:        pc.info.Subject,
					CertExpiration: pc.info.CertExpiration,
					Target:         targetName,
					Status:         computeCertStatus(pc.notAfter, vfPtr, now),
					Type:           targetType,
					Pem:            pc.info.Pem,
				}
				if vfPtr != nil {
					start := vfPtr.start.Format(time.RFC3339)
					info.ValidForStart = &start
					if !vfPtr.end.IsZero() {
						end := vfPtr.end.Format(time.RFC3339)
						info.ValidForEnd = &end
					}
				}
				result.Data = append(result.Data, info)
			}
		}
	}

	// If there were errors fetching all certificate targets, return an error
	if len(fetchErrors) > 0 && len(result.Data) == 0 {
		return models.CertificateInfoList{}, http.StatusInternalServerError,
			fmt.Errorf("failed to fetch all certificate targets: %s", strings.Join(fetchErrors, "; "))
	}

	return result, http.StatusOK, nil
}

func (s *trustService) GetAllTargets(ctx context.Context, tufRepoUrl string) (models.TargetsList, int, error) {
	// Get targets directly from TUF metadata
	s.repoLock.RLock()
	repo := s.repo
	repoReady := s.repoReady
	s.repoLock.RUnlock()

	if !repoReady || repo == nil {
		return models.TargetsList{}, http.StatusServiceUnavailable, fmt.Errorf("TUF repository not ready")
	}

	// Acquire repo.lock to safely access repo.updater
	repo.lock.RLock()
	targetsMeta := repo.updater.GetTrustedMetadataSet().Targets["targets"]
	if targetsMeta == nil {
		repo.lock.RUnlock()
		return models.TargetsList{}, http.StatusInternalServerError, fmt.Errorf("targets metadata not available")
	}

	targetsBytes, err := targetsMeta.ToBytes(true)
	repo.lock.RUnlock()

	if err != nil {
		return models.TargetsList{}, http.StatusInternalServerError, fmt.Errorf("failed to get targets bytes: %w", err)
	}

	targetMetadataSpecs, err := extractTargetMetadataInfo(targetsBytes)
	if err != nil {
		return models.TargetsList{}, http.StatusInternalServerError, fmt.Errorf("extracting target metadata: %w", err)
	}

	result := models.TargetsList{}
	var fetchErrors []string

	for targetName, spec := range targetMetadataSpecs {
		// Fetch target content from TUF cache
		targetContent, statusCode, err := s.GetTargetFromTUFRepo(ctx, tufRepoUrl, targetName)
		if err != nil {
			errMsg := fmt.Sprintf("failed to get target %s: %v", targetName, err)
			log.Print(errMsg)
			fetchErrors = append(fetchErrors, errMsg)
			continue
		}
		if statusCode != http.StatusOK {
			errMsg := fmt.Sprintf("failed to get target %s: status code %d", targetName, statusCode)
			log.Print(errMsg)
			fetchErrors = append(fetchErrors, errMsg)
			continue
		}

		result.Data = append(result.Data, models.TargetInfo{
			Name:    targetName,
			Type:    spec["type"],
			Status:  spec["status"], // Status from TUF metadata (Active, Expired, etc.)
			Content: targetContent.Content,
		})
	}

	// If there were errors fetching all targets, return an error
	if len(fetchErrors) > 0 && len(result.Data) == 0 {
		return models.TargetsList{}, http.StatusInternalServerError,
			fmt.Errorf("failed to fetch all targets: %s", strings.Join(fetchErrors, "; "))
	}

	return result, http.StatusOK, nil
}

func (s *trustService) GetTrustCoverage(ctx context.Context, timeWindow string, environment *string, tufRepoUrl string) (models.TrustCoverageResponse, int, error) {
	mockMode := os.Getenv("MOCK_MODE")
	if mockMode != "true" {
		return models.TrustCoverageResponse{}, http.StatusServiceUnavailable, fmt.Errorf("coverage data not available - set MOCK_MODE=true for mock data")
	}

	return getMockTrustCoverage(), http.StatusOK, nil
}

func getMockTrustCoverage() models.TrustCoverageResponse {
	totalArtifacts := 1000
	attestedCount := 610

	return models.TrustCoverageResponse{
		TotalArtifacts:     totalArtifacts,
		AttestedCount:      attestedCount,
		VerifiedPercentage: float32(attestedCount) / float32(totalArtifacts) * 100,
		AttestedPercentage: float32(attestedCount) / float32(totalArtifacts) * 100,
		UpdatedAt:          time.Now().UTC(),
	}
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
	// Lock is already held by the caller (defer at line 393)
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

				// Create a timeout context for the refresh operation
				refreshCtx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
				defer cancel()

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

				// Run refresh with timeout by using a channel
				refreshDone := make(chan error, 1)
				go func() {
					refreshDone <- newUpdater.Refresh()
				}()

				select {
				case err := <-refreshDone:
					if err != nil {
						log.Printf("TUF: Refresh failed for %s: %v", url, err)
						repo.lock.Unlock()
						return
					}
				case <-refreshCtx.Done():
					log.Printf("TUF: Refresh timed out for %s", url)
					repo.lock.Unlock()
					return
				}

				repo.updater = newUpdater
				repo.lastRefresh = time.Now().UTC()
				repo.lock.Unlock()

				log.Printf("TUF: Successfully refreshed repository %s", url)
			}(repo, url)
		}
	}
}

// preFetchAllTargets downloads all targets in parallel to warm up the cache
func (s *trustService) preFetchAllTargets(ctx context.Context, repo *tufRepository) {
	log.Printf("TUF: Starting pre-fetch of all targets from %s", repo.remoteMetadataURL)

	// Get all target names from metadata
	repo.lock.RLock()
	targetsMeta := repo.updater.GetTrustedMetadataSet().Targets["targets"]
	if targetsMeta == nil {
		repo.lock.RUnlock()
		log.Printf("TUF: Pre-fetch skipped - targets metadata not available")
		return
	}

	targetsBytes, err := targetsMeta.ToBytes(true)
	repo.lock.RUnlock()

	if err != nil {
		log.Printf("TUF: Pre-fetch failed to get targets bytes: %v", err)
		return
	}

	targetMetadataSpecs, err := extractTargetMetadataInfo(targetsBytes)
	if err != nil {
		log.Printf("TUF: Pre-fetch failed to extract target metadata: %v", err)
		return
	}

	// Create a timeout context for pre-fetching
	prefetchCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// Use a WaitGroup to parallelize target downloads
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Limit to 10 concurrent downloads

	successCount := 0
	failureCount := 0
	var mu sync.Mutex

	for targetName := range targetMetadataSpecs {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-prefetchCtx.Done():
				return
			}

			// Fetch target
			_, _, err := s.GetTargetFromTUFRepo(prefetchCtx, repo.remoteMetadataURL, name)
			mu.Lock()
			if err != nil {
				failureCount++
			} else {
				successCount++
			}
			mu.Unlock()
		}(targetName)
	}

	wg.Wait()
	log.Printf("TUF: Pre-fetch completed - %d succeeded, %d failed out of %d targets",
		successCount, failureCount, len(targetMetadataSpecs))
}

// Close cancels the periodic refreshes
func (s *trustService) Close() error {
	s.cancel() // Stop the background refresh
	return nil
}

// GetTUFRepoURL returns the configured TUF repository URL
func (s *trustService) GetTUFRepoURL() string {
	return s.tufRepoUrl
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

func metadataInfoFromVersionAndExpires(version int64, expires time.Time) models.MetadataInfo {
	now := time.Now().UTC()
	var status string
	switch {
	case expires.Before(now):
		status = "expired"
	case expires.Sub(now) < 30*24*time.Hour:
		status = "expiring"
	default:
		status = "valid"
	}
	return models.MetadataInfo{
		Version: strconv.FormatInt(version, 10),
		Expires: expires.Format(time.RFC3339),
		Status:  status,
	}
}

func extractRootMetadataInfo(rootMetadataBytes []byte) (models.MetadataInfo, error) {
	var parsed struct {
		Signed struct {
			Expired string `json:"expires"`
			Version int    `json:"version"`
		} `json:"signed"`
	}

	if err := json.Unmarshal(rootMetadataBytes, &parsed); err != nil {
		return models.MetadataInfo{}, fmt.Errorf("unmarshal root metadata: %w", err)
	}

	expiresTime, err := time.Parse(time.RFC3339, parsed.Signed.Expired)
	if err != nil {
		return models.MetadataInfo{}, fmt.Errorf("parse expires time: %w", err)
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

	return models.MetadataInfo{
		Version: strconv.Itoa(parsed.Signed.Version),
		Expires: parsed.Signed.Expired,
		Status:  status,
	}, nil
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

type parsedCertEntry struct {
	info        models.CertificateInfo
	fingerprint string
	notAfter    time.Time
}

// extractCertDetails extracts subject, issuer & status from a PEM certificate
func extractCertDetails(certPEM string) ([]parsedCertEntry, error) {
	var results []parsedCertEntry
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
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		results = append(results, parsedCertEntry{
			info: models.CertificateInfo{
				Subject:        cert.Subject.String(),
				Issuer:         cert.Issuer.String(),
				CertExpiration: cert.NotAfter.UTC().Format(time.RFC3339),
				Pem:            string(pemBytes),
			},
			fingerprint: certFingerprint(cert.Raw),
			notAfter:    cert.NotAfter,
		})
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no valid certificates found")
	}
	return results, nil
}

func certFingerprint(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

type validForWindow struct {
	start time.Time
	end   time.Time
}

func computeCertStatus(notAfter time.Time, validFor *validForWindow, now time.Time) models.CertificateStatus {
	expired := !notAfter.IsZero() && now.After(notAfter)
	if expired {
		return models.Expired
	}
	if validFor != nil && !validFor.end.IsZero() && now.After(validFor.end) {
		return models.Revoked
	}
	if !notAfter.IsZero() && notAfter.Sub(now) <= 30*24*time.Hour {
		return models.Expiring
	}
	return models.Active
}

func (s *trustService) getValidForLookup(ctx context.Context, tufRepoUrl string) map[string]validForWindow {
	s.validForMu.RLock()
	if s.validForCache != nil && urlsEqual(s.validForRepoUrl, tufRepoUrl) && time.Now().Before(s.validForExpiry) {
		cached := s.validForCache
		s.validForMu.RUnlock()
		return cached
	}
	s.validForMu.RUnlock()

	v, _, _ := s.validForFlight.Do(tufRepoUrl, func() (interface{}, error) {
		lookup := buildValidForLookup(context.Background(), s, tufRepoUrl)

		if len(lookup) > 0 {
			s.validForMu.Lock()
			s.validForCache = lookup
			s.validForRepoUrl = tufRepoUrl
			s.validForExpiry = time.Now().Add(s.refreshInterval)
			s.validForMu.Unlock()
		}

		return lookup, nil
	})

	return v.(map[string]validForWindow)
}

func buildValidForLookup(ctx context.Context, s *trustService, tufRepoUrl string) map[string]validForWindow {
	lookup := make(map[string]validForWindow)

	targetContent, statusCode, err := s.GetTargetFromTUFRepo(ctx, tufRepoUrl, "trusted_root.json")
	if err != nil || statusCode != http.StatusOK {
		log.Printf("failed to fetch trusted_root.json for validFor enrichment (statusCode=%d): %v", statusCode, err)
		return lookup
	}

	trustedRoot, err := root.NewTrustedRootFromJSON([]byte(targetContent.Content))
	if err != nil {
		log.Printf("failed to parse trusted_root.json for validFor enrichment: %v", err)
		return lookup
	}

	for _, ca := range trustedRoot.FulcioCertificateAuthorities() {
		fca, ok := ca.(*root.FulcioCertificateAuthority)
		if !ok {
			continue
		}
		w := validForWindow{start: fca.ValidityPeriodStart, end: fca.ValidityPeriodEnd}
		if fca.Root != nil {
			lookup[certFingerprint(fca.Root.Raw)] = w
		}
		for _, intermediate := range fca.Intermediates {
			lookup[certFingerprint(intermediate.Raw)] = w
		}
	}

	for _, tsa := range trustedRoot.TimestampingAuthorities() {
		sta, ok := tsa.(*root.SigstoreTimestampingAuthority)
		if !ok {
			continue
		}
		w := validForWindow{start: sta.ValidityPeriodStart, end: sta.ValidityPeriodEnd}
		if sta.Root != nil {
			lookup[certFingerprint(sta.Root.Raw)] = w
		}
		if sta.Leaf != nil {
			lookup[certFingerprint(sta.Leaf.Raw)] = w
		}
		for _, intermediate := range sta.Intermediates {
			lookup[certFingerprint(intermediate.Raw)] = w
		}
	}

	return lookup
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
