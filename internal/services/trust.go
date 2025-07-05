package services

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/securesign/rhtas-console/internal/models"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

type TrustService interface {
	GetTrustConfig(ctx context.Context, tufRepoUrl string) (models.TrustConfig, error)
	GetTrustRootMetadataInfo(tufRepoUrl string) (models.RootMetadataInfoList, error)
	GetTargetsList(ctx context.Context, tufRepoUrl string) (models.TargetsList, error)
	GetTarget(ctx context.Context, tufRepoUrl string, target string) (models.TargetContent, error)
	GetCertificatesInfo(ctx context.Context, tufRepoUrl string) (models.CertificateInfoList, error)
}

type trustService struct{}

func NewTrustService() TrustService {
	return &trustService{}
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
	opts := buildTufOptions(tufRepoUrl)
	var results models.RootMetadataInfoList
	rootBytesList, err := fetchAllTufRootMetadata(opts)
	if err != nil {
		return models.RootMetadataInfoList{}, fmt.Errorf("fetching TUF root metadata: %w", err)
	}
	for _, rootBytes := range rootBytesList {
		rootInfo, err := extractRootMetadataInfo(rootBytes)
		if err != nil {
			return models.RootMetadataInfoList{}, fmt.Errorf("extracting root metadata info: %w", err)
		}
		results.Data = append(results.Data, rootInfo)
	}

	return results, nil
}

func (s *trustService) GetTargetsList(ctx context.Context, tufRepoUrl string) (models.TargetsList, error) {
	opts := buildTufOptions(tufRepoUrl)
	tufCfg, err := buildTufConfig(opts)
	if err != nil {
		return models.TargetsList{}, err
	}

	up, err := updater.New(tufCfg)
	if err != nil {
		return models.TargetsList{}, fmt.Errorf("failed to create updater: %w", err)
	}

	if err := up.Refresh(); err != nil {
		return models.TargetsList{}, fmt.Errorf("failed to refresh updater: %w", err)
	}

	// Get Targets list
	targetFiles := up.GetTopLevelTargets()
	var targetList []string
	for target := range targetFiles {
		targetList = append(targetList, target)
	}

	return models.TargetsList{Targets: targetList}, nil
}

func (s *trustService) GetTarget(ctx context.Context, tufRepoUrl string, target string) (models.TargetContent, error) {
	opts := buildTufOptions(tufRepoUrl)
	tufCfg, err := buildTufConfig(opts)
	if err != nil {
		return models.TargetContent{}, err
	}

	up, err := updater.New(tufCfg)
	if err != nil {
		return models.TargetContent{}, fmt.Errorf("failed to create updater: %w", err)
	}

	if err := up.Refresh(); err != nil {
		return models.TargetContent{}, fmt.Errorf("failed to refresh updater: %w", err)
	}

	// Get Target content
	const filePath = ""
	ti, err := up.GetTargetInfo(target)
	if err != nil {
		return models.TargetContent{}, fmt.Errorf("getting info for target \"%s\": %w", target, err)
	}
	path, tb, err := up.FindCachedTarget(ti, filePath)
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
	_, tb, err = up.DownloadTarget(ti, filePath, targetsBaseURL)
	if err != nil {
		return models.TargetContent{}, fmt.Errorf("failed to download target file %s - %w", target, err)
	}

	return models.TargetContent{Content: string(tb)}, nil
}

func (s *trustService) GetCertificatesInfo(ctx context.Context, tufRepoUrl string) (models.CertificateInfoList, error) {
	opts := buildTufOptions(tufRepoUrl)
	targetsBytes, err := fetchTufTargetsMetadata(opts)
	if err != nil {
		return models.CertificateInfoList{}, fmt.Errorf("fetching TUF target metadata: %w", err)
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

// buildTufOptions returns TUF options with the provided or default repository URL.
func buildTufOptions(tufRepoUrl string) *tuf.Options {
	opts := tuf.DefaultOptions()
	if tufRepoUrl != "" {
		opts.RepositoryBaseURL = tufRepoUrl
	} else {
		opts.RepositoryBaseURL = "https://tuf-repo-cdn.sigstore.dev"
	}
	return opts
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

// fetchAllTufRootMetadata retrieves all versions of the TUF root metadata as byte slices.
func fetchAllTufRootMetadata(opts *tuf.Options) ([][]byte, error) {
	tufCfg, err := buildTufConfig(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to build TUF config: %w", err)
	}

	if tufCfg.RemoteMetadataURL == "" {
		return nil, fmt.Errorf("RemoteMetadataURL is empty")
	}
	parsedURL, err := url.Parse(tufCfg.RemoteMetadataURL)
	if err != nil {
		return nil, fmt.Errorf("invalid RemoteMetadataURL %s: %w", tufCfg.RemoteMetadataURL, err)
	}
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return nil, fmt.Errorf("unsupported URL scheme in RemoteMetadataURL: %s", parsedURL.Scheme)
	}
	// Ensure trailing slash for consistent URL joining
	if !strings.HasSuffix(parsedURL.Path, "/") {
		parsedURL.Path += "/"
	}
	tufCfg.RemoteMetadataURL = parsedURL.String()

	up, err := updater.New(tufCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create updater: %w", err)
	}

	if err := up.Refresh(); err != nil {
		return nil, fmt.Errorf("failed to refresh updater: %w", err)
	}
	// Get the latest root metadata
	latestRootMeta := up.GetTrustedMetadataSet().Root
	if latestRootMeta == nil {
		return nil, fmt.Errorf("latest root metadata not available")
	}
	// Extract the version number from the latest root metadata
	latestVersion := latestRootMeta.Signed.Version
	if latestVersion < 1 {
		return nil, fmt.Errorf("invalid latest root version: %d", latestVersion)
	}

	// Collect all root metadata versions
	var allRootBytes [][]byte

	// Add the latest root metadata
	latestRootBytes, err := latestRootMeta.ToBytes(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get signed latest root bytes: %w", err)
	}
	allRootBytes = append(allRootBytes, latestRootBytes)

	// Fetch previous versions (1.root.json, 2.root.json...N-1.root.json)
	for version := 1; version < int(latestVersion); version++ {
		rootFilename := fmt.Sprintf("%d.root.json", version)
		metadataURL, err := url.JoinPath(tufCfg.RemoteMetadataURL, rootFilename)
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
	return allRootBytes, nil
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
		return models.RootMetadataInfo{}, fmt.Errorf("unmarshal targets metadata: %w", err)
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

// fetchTufTargetsMetadata retrieves TUF target metadata as byte slices.
func fetchTufTargetsMetadata(opts *tuf.Options) ([]byte, error) {
	tufCfg, err := buildTufConfig(opts)
	if err != nil {
		return nil, err
	}

	up, err := updater.New(tufCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create updater: %w", err)
	}

	if err := up.Refresh(); err != nil {
		return nil, fmt.Errorf("failed to refresh updater: %w", err)
	}

	// Get raw targets metadata
	targetsMeta := up.GetTrustedMetadataSet().Targets["targets"]
	if targetsMeta == nil {
		return nil, fmt.Errorf("targets metadata not available")
	}

	targetsBytes, err := targetsMeta.ToBytes(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get signed root bytes: %w", err)
	}

	return targetsBytes, nil
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
