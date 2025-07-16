package services

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	GetTargetsList(ctx context.Context, tufRepoUrl string) (models.TargetsList, error)
	GetTarget(ctx context.Context, tufRepoUrl string, target string) (models.TargetContent, error)
	GetCertificatesInfo(ctx context.Context, tufRepoUrl string) (models.CertificateInfoList, error)
}

// trustService manages TUF repository metadata
type trustService struct {
	repoLock        sync.RWMutex
	repo            *tufRepository
	repoReady       bool
	refreshInterval time.Duration
	tufRepoUrl      string
}

// tufRepository holds the TUF updater and associated metadata for a single repository
type tufRepository struct {
	updater           *updater.Updater
	opts              *tuf.Options
	lock              sync.RWMutex
	lastRefresh       time.Time
	refreshInProgress bool
	remoteMetadataURL string
	url               string
}

func NewTrustService() TrustService {
	refreshInterval := 5 * time.Minute
	if envInterval := os.Getenv("TUF_REFRESH_INTERVAL"); envInterval != "" {
		if parsed, err := time.ParseDuration(envInterval); err == nil && parsed > 0 {
			refreshInterval = parsed
		}
	}

	s := &trustService{
		refreshInterval: refreshInterval,
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

func (s *trustService) GetTargetsList(ctx context.Context, tufRepoUrl string) (models.TargetsList, error) {
	repo, err := s.getOrCreateUpdater(tufRepoUrl)
	if err != nil {
		return models.TargetsList{}, err
	}
	repo.lock.RLock()
	defer repo.lock.RUnlock()

	// Check if context is cancelled
	if ctx.Err() != nil {
		return models.TargetsList{}, ctx.Err()
	}

	// Get Targets list
	targetFiles := repo.updater.GetTopLevelTargets()
	var targetList []string
	for target := range targetFiles {
		targetList = append(targetList, target)
	}

	return models.TargetsList{Targets: targetList}, nil
}

func (s *trustService) GetTarget(ctx context.Context, tufRepoUrl string, target string) (models.TargetContent, error) {
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

func (s *trustService) GetCertificatesInfo(ctx context.Context, tufRepoUrl string) (models.CertificateInfoList, error) {
	repo, err := s.getOrCreateUpdater(tufRepoUrl)
	if err != nil {
		return models.CertificateInfoList{}, err
	}

	repo.lock.RLock()
	defer repo.lock.RUnlock()

	// Check if context is cancelled
	if ctx.Err() != nil {
		return models.CertificateInfoList{}, ctx.Err()
	}

	targetsMeta := repo.updater.GetTrustedMetadataSet().Targets["targets"]
	if targetsMeta == nil {
		return models.CertificateInfoList{}, fmt.Errorf("targets metadata not available")
	}

	targetsBytes, err := targetsMeta.ToBytes(true)
	if err != nil {
		return models.CertificateInfoList{}, fmt.Errorf("failed to get targets bytes: %w", err)
	}

	targetMetadataSpecs, err := extractTargetMetadataInfo(targetsBytes)
	result := models.CertificateInfoList{}
	if err != nil {
		return models.CertificateInfoList{}, fmt.Errorf("fetching TUF root metadata: %w", err)
	}
	for target, info := range targetMetadataSpecs {
		// Only targets of type certificate
		if strings.ToLower(info["type"]) == "fulcio" || strings.ToLower(info["type"]) == "tsa" {
			cert_content, err := s.GetTarget(ctx, tufRepoUrl, target)
			if err != nil {
				return models.CertificateInfoList{}, fmt.Errorf("getting target certificate content: %w", err)
			}
			cert_info_list, err := extractCertDetails(cert_content.Content)
			if err != nil {
				return models.CertificateInfoList{}, fmt.Errorf("extracting subject and issuer: %w", err)
			}
			for _, cert_info := range cert_info_list.Data {
				result.Data = append(result.Data, models.CertificateInfo{
					Issuer:     cert_info.Issuer,
					Subject:    cert_info.Subject,
					Expiration: cert_info.Expiration,
					Target:     target,
					Status:     info["status"],
					Type:       info["type"],
				})
			}
		}
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
		url:               tufRepoUrl,
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
			defer repo.lock.Unlock()
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
			log.Printf("TUF: Successfully refreshed repository %s", url)
		}(repo, url)
	}
}

// buildTufOptions returns TUF options with the provided or default repository URL.
func buildTufOptions(tufRepoUrl string) (*tuf.Options, error) {
	opts := tuf.DefaultOptions()
	if envRepoUrl := os.Getenv("TUF_REPO_URL"); envRepoUrl != "" {
		opts.RepositoryBaseURL = envRepoUrl
	} else if tufRepoUrl != "" {
		opts.RepositoryBaseURL = tufRepoUrl
	} else {
		opts.RepositoryBaseURL = publicGoodInstance
	}

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
		entry := models.CertificateInfo{
			Subject:    cert.Subject.String(),
			Issuer:     cert.Issuer.String(),
			Expiration: cert.NotAfter.String(),
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
