package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/securesign/rhtas-console/internal/errors"
	"github.com/securesign/rhtas-console/internal/models"
)

type ArtifactService interface {
	SignArtifact(ctx context.Context, req models.SignArtifactRequest) (models.SignArtifactResponse, error)
	VerifyArtifact(ctx context.Context, req models.VerifyArtifactRequest) (models.VerifyArtifactResponse, error)
	GetArtifactPolicies(ctx context.Context, artifact string) (models.ArtifactPolicies, error)
	GetImageMetadata(ctx context.Context, image string, username string, password string) (models.ImageMetadataResponse, error)
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

func (s *artifactService) GetImageMetadata(ctx context.Context, image string, username string, password string) (models.ImageMetadataResponse, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return models.ImageMetadataResponse{}, fmt.Errorf("invalid image URI: %w", err)
	}

	auth := authn.Anonymous
	if username != "" && password != "" {
		auth = &authn.Basic{Username: username, Password: password}
	}

	opts := []remote.Option{remote.WithAuth(auth), remote.WithContext(ctx)}

	descriptor, err := remote.Get(ref, opts...)
	if err != nil {
		if isNotFound(err) {
			return models.ImageMetadataResponse{}, fmt.Errorf("image not found: %w", err)
		} else if isAuthError(err) {
			return models.ImageMetadataResponse{}, fmt.Errorf("authentication failed: %w", err)
		} else {
			return models.ImageMetadataResponse{}, fmt.Errorf("failed to fetch metadata: %w", err)
		}
	}

	// Fetch digest
	img, err := remote.Image(ref, opts...)
	if err != nil {
		return models.ImageMetadataResponse{}, fmt.Errorf("failed to fetch image: %w", err)
	}
	digest, err := img.Digest()
	if err != nil {
		return models.ImageMetadataResponse{}, fmt.Errorf("failed to compute digest: %w", err)
	}

	// Extract config metadata
	configFile, err := img.ConfigFile()
	if err != nil {
		return models.ImageMetadataResponse{}, fmt.Errorf("failed to fetch config file: %w", err)
	}

	created := configFile.Created
	labels := configFile.Config.Labels
	if len(labels) == 0 {
		labels = nil
	}

	response := models.ImageMetadataResponse{
		Image: &image,
		Metadata: models.Metadata{
			MediaType: string(descriptor.MediaType),
			Size:      descriptor.Size,
			Created:   &created.Time,
			Labels:    &labels,
		},
		Digest: digest.String(),
	}
	return response, nil
}

// isNotFound checks if the error indicates the image was not found
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.IsArtifactError(err, "not found") ||
		errors.IsArtifactError(err, "404") ||
		errors.IsArtifactError(err, "name unknown")
}

// isAuthError checks if the error indicates an authentication failure
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	return errors.IsArtifactError(err, "unauthorized") ||
		errors.IsArtifactError(err, "401") ||
		errors.IsArtifactError(err, "authentication required")
}
