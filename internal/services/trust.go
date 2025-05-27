package services

import (
	"context"
	"time"

	"github.com/securesign/rhtas-console/internal/models"
)

type TrustService interface {
	GetTrustConfig(ctx context.Context) (models.TrustConfig, error)
}

type trustService struct{}

func NewTrustService() TrustService {
	return &trustService{}
}

func (s *trustService) GetTrustConfig(ctx context.Context) (models.TrustConfig, error) {
	// TODO: complete logic
	expiration, _ := time.Parse("2006-01-02", "2025-12-31T12:00:00Z")
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
		TufRoot: struct {
			Expires time.Time `json:"expires"`
			Version int       `json:"version"`
		}{
			Expires: expiration,
			Version: 1,
		},
	}, nil
}
