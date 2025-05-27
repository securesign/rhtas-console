package services

import (
	"context"
	"time"

	"github.com/securesign/rhtas-console/internal/models"
)

type ArtifactService interface {
	SignArtifact(ctx context.Context, req models.SignArtifactRequest) (models.SignArtifactResponse, error)
	VerifyArtifact(ctx context.Context, req models.VerifyArtifactRequest) (models.VerifyArtifactResponse, error)
	GetArtifactPolicies(ctx context.Context, artifact string) (models.ArtifactPolicies, error)
}

type artifactService struct{}

func NewArtifactService() ArtifactService {
	return &artifactService{}
}

func (s *artifactService) SignArtifact(ctx context.Context, req models.SignArtifactRequest) (models.SignArtifactResponse, error) {
	// TODO: complete logic
	return models.SignArtifactResponse{
		Certificate: nil,
		LogEntry:    nil,
		Signature:   "stub-signature",
		Success:     true,
	}, nil
}

func (s *artifactService) VerifyArtifact(ctx context.Context, req models.VerifyArtifactRequest) (models.VerifyArtifactResponse, error) {
	// TODO: complete logic
	return models.VerifyArtifactResponse{
		Details:  nil,
		Message:  "Successful verification",
		Verified: true,
	}, nil
}

func (s *artifactService) GetArtifactPolicies(ctx context.Context, artifact string) (models.ArtifactPolicies, error) {
	// TODO: complete logic
	now := time.Now()
	issuer := "ExampleIssuer"
	subject := "ArtifactSubject"
	attType := "Signature"
	policyName := "SecurityScan"
	policyStatus := "Compliant"
	return models.ArtifactPolicies{
		Artifact: artifact,
		Attestations: []struct {
			IssuedAt *time.Time `json:"issuedAt,omitempty"`
			Issuer   *string    `json:"issuer,omitempty"`
			Subject  *string    `json:"subject,omitempty"`
			Type     *string    `json:"type,omitempty"`
		}{
			{
				IssuedAt: &now,
				Issuer:   &issuer,
				Subject:  &subject,
				Type:     &attType,
			},
		},
		Policies: []struct {
			LastChecked *time.Time `json:"lastChecked,omitempty"`
			Name        *string    `json:"name,omitempty"`
			Status      *string    `json:"status,omitempty"`
		}{
			{
				LastChecked: &now,
				Name:        &policyName,
				Status:      &policyStatus,
			},
		},
	}, nil
}
