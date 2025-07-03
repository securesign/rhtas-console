package services

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/securesign/rhtas-console/internal/models"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

type TrustService interface {
	GetTrustConfig(ctx context.Context, tufRepoUrl string) (models.TrustConfig, error)
	GetTrustRootMetadataInfo(ctx context.Context, tufRepoUrl string) (models.RootMetadataInfo, error)
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

func (s *trustService) GetTrustRootMetadataInfo(ctx context.Context, tufRepoUrl string) (models.RootMetadataInfo, error) {
	opts := buildTufOptions(tufRepoUrl)
	rootBytes, err := fetchTufRootMetadata(opts)
	if err != nil {
		return models.RootMetadataInfo{}, fmt.Errorf("fetching TUF root metadata: %w", err)
	}
	rootInfo, err := extractRootMetadataInfo(rootBytes)
	if err != nil {
		return models.RootMetadataInfo{}, fmt.Errorf("extracting root metadata info: %w", err)
	}
	return models.RootMetadataInfo{
		Version: rootInfo["version"],
		Expires: rootInfo["expires"],
		Status:  rootInfo["status"],
	}, nil
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

func fetchTufRootMetadata(opts *tuf.Options) ([]byte, error) {
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

	// Get raw root metadata
	rootMeta := up.GetTrustedMetadataSet().Root
	if rootMeta == nil {
		return nil, fmt.Errorf("root metadata not available")
	}

	rootBytes, err := rootMeta.ToBytes(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get signed root bytes: %w", err)
	}

	return rootBytes, nil
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

	rootMetadataInfo := make(map[string]string)
	rootMetadataInfo = map[string]string{
		"version": strconv.Itoa(parsed.Signed.Version),
		"expires": parsed.Signed.Expired,
		"status":  status,
	}

	return rootMetadataInfo, nil
}
