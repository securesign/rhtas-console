package services

import (
	"context"
	"encoding/json"
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
		entry := models.RootMetadataInfo{
			Version: rootInfo["version"],
			Expires: rootInfo["expires"],
			Status:  rootInfo["status"],
		}
		results = append(results, entry)
	}

	return results, nil
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

// Retrieves TUF root metadata info including version, expiration, and status.
func extractRootMetadataInfo(rootMetadataBytes []byte) (map[string]string, error) {
	var parsed struct {
		Signed struct {
			Expired string `json:"expires"`
			Version int    `json:"version"`
		} `json:"signed"`
	}

	if err := json.Unmarshal(rootMetadataBytes, &parsed); err != nil {
		return nil, fmt.Errorf("unmarshal targets metadata: %w", err)
	}

	expiresTime, err := time.Parse(time.RFC3339, parsed.Signed.Expired)
	if err != nil {
		return nil, fmt.Errorf("parse expires time: %w", err)
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

	rootMetadataInfo := map[string]string{
		"version": strconv.Itoa(parsed.Signed.Version),
		"expires": parsed.Signed.Expired,
		"status":  status,
	}

	return rootMetadataInfo, nil
}
