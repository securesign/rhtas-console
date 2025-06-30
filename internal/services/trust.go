package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/securesign/rhtas-console/internal/models"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

type TrustService interface {
	GetTrustConfig(ctx context.Context, tufRepoUrl string) (models.TrustConfig, error)
	GetTrustRootMetadata(ctx context.Context, tufRepoUrl string) (models.RootMetadata, error)
}

type trustService struct{}

func NewTrustService() TrustService {
	return &trustService{}
}

func (s *trustService) GetTrustConfig(ctx context.Context, tufRepoUrl string) (models.TrustConfig, error) {
	opts := tuf.DefaultOptions()
	if tufRepoUrl != "" {
		opts.RepositoryBaseURL = tufRepoUrl
	} else {
		opts.RepositoryBaseURL = "https://tuf-repo-cdn.sigstore.dev"
	}
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

func (s *trustService) GetTrustRootMetadata(ctx context.Context, tufRepoUrl string) (models.RootMetadata, error) {
	opts := tuf.DefaultOptions()
	if tufRepoUrl != "" {
		opts.RepositoryBaseURL = tufRepoUrl
	} else {
		opts.RepositoryBaseURL = "https://tuf-repo-cdn.sigstore.dev"
	}
	rootBytes, err := fetchTufRootMetadata(opts)
	if err != nil {
		return models.RootMetadata{}, fmt.Errorf("fetching TUF root metadata: %w", err)
	}

	var prettyRoot bytes.Buffer
	if err := json.Indent(&prettyRoot, rootBytes, "", "    "); err != nil {
		return models.RootMetadata{}, fmt.Errorf("formatting root JSON: %w", err)
	}

	return models.RootMetadata{
		TufRootJson: prettyRoot.Bytes(),
	}, nil
}

func fetchTufRootMetadata(opts *tuf.Options) ([]byte, error) {
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
