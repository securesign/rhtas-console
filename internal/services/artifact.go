package services

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/securesign/rhtas-console/internal/models"
	"github.com/securesign/rhtas-console/internal/services/verify"
)

type ArtifactService interface {
	VerifyArtifact(req models.VerifyArtifactRequest) (models.VerifyArtifactResponse, error)
	GetArtifactPolicies(ctx context.Context, artifact string) (models.ArtifactPolicies, error)
	GetImageMetadata(ctx context.Context, image string, username string, password string) (models.ImageMetadataResponse, error)
}

type artifactService struct{}

func NewArtifactService() ArtifactService {
	return &artifactService{}
}

func (s *artifactService) VerifyArtifact(req models.VerifyArtifactRequest) (models.VerifyArtifactResponse, error) {
	verifyOpts := verify.NewVerifyOptions()

	if req.OciImage == "" {
		return models.VerifyArtifactResponse{}, fmt.Errorf("ociImage is a required parameter and cannot be empty")
	}
	verifyOpts.OCIImage = req.OciImage

	if req.Bundle != nil {
		verifyOpts.Bundle = *req.Bundle
	}
	if req.ExpectedOIDIssuer != nil {
		verifyOpts.ExpectedOIDIssuer = *req.ExpectedOIDIssuer
	}
	if req.ExpectedOIDIssuerRegex != nil {
		verifyOpts.ExpectedOIDIssuerRegex = *req.ExpectedOIDIssuerRegex
	}
	if req.ExpectedSAN != nil {
		verifyOpts.ExpectedSAN = *req.ExpectedSAN
	}
	if req.ExpectedSANRegex != nil {
		verifyOpts.ExpectedSANRegex = *req.ExpectedSANRegex
	}

	tufRepoUrl := ""
	if req.TufRepoUrl != nil {
		tufRepoUrl = *req.TufRepoUrl
	} else {
		tufRepoUrl = os.Getenv("TUF_REPO_URL")
	}

	if tufRepoUrl == "" {
		return models.VerifyArtifactResponse{}, fmt.Errorf("tufRepoUrl is a required parameter and cannot be empty. Provide it either in request or as the TUF_REPO_URL environment variable")
	}
	verifyOpts.TUFRootURL = tufRepoUrl

	if req.ArtifactDigest != nil {
		verifyOpts.ArtifactDigest = *req.ArtifactDigest
	}
	if req.ArtifactDigestAlgorithm != nil {
		verifyOpts.ArtifactDigestAlgorithm = *req.ArtifactDigestAlgorithm
	}
	if req.RequireTimestamp != nil {
		verifyOpts.RequireTimestamp = *req.RequireTimestamp
	}
	if req.RequireCTLog != nil {
		verifyOpts.RequireCTLog = *req.RequireCTLog
	}
	if req.RequireTLog != nil {
		verifyOpts.RequireTLog = *req.RequireTLog
	}
	if req.PredicateType != nil {
		verifyOpts.PredicateType = *req.PredicateType
	}

	detailsJSON, err := verify.VerifyArtifact(verifyOpts)
	if err != nil {
		return models.VerifyArtifactResponse{}, err
	}

	return detailsJSON, nil
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

func (s *artifactService) GetImageMetadata(ctx context.Context, image string, username string, password string) (models.ImageMetadataResponse, error) {
	return verify.GetImageMetadata(image, username, password)
}
