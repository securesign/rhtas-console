package services

import (
	"context"

	"github.com/securesign/rhtas-console/internal/models"
)

type RekorService interface {
	GetRekorEntry(ctx context.Context, uuid string) (models.TransparencyLogEntry, error)
	GetRekorPublicKey(ctx context.Context) (models.RekorPublicKey, error)
}

type rekorService struct{}

func NewRekorService() RekorService {
	return &rekorService{}
}

func (s *rekorService) GetRekorEntry(ctx context.Context, uuid string) (models.TransparencyLogEntry, error) {
	// TODO: Implement actual API call to Rekor server
	return models.TransparencyLogEntry{}, nil
}

func (s *rekorService) GetRekorPublicKey(ctx context.Context) (models.RekorPublicKey, error) {
	// TODO: complete logic
	return models.RekorPublicKey{
		PublicKey: "-----BEGIN PUBLIC KEY-----\nstub-key\n-----END PUBLIC KEY-----",
	}, nil
}
