package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	console_errors "github.com/securesign/rhtas-console/internal/errors"
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

	if req.OciImage != nil {
		verifyOpts.OCIImage = *req.OciImage
	}
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
	if req.TufRootURL != nil {
		verifyOpts.TUFRootURL = *req.TufRootURL
	} else {
		verifyOpts.TUFRootURL = TufPublicGoodInstance
	}
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
		return models.VerifyArtifactResponse{
			Verified: false,
			Details:  map[string]interface{}{"error": err.Error()},
		}, err
	}

	var details map[string]interface{}
	if unmarshalErr := json.Unmarshal([]byte(detailsJSON), &details); unmarshalErr != nil {
		details = map[string]interface{}{"raw": detailsJSON}
	}

	return models.VerifyArtifactResponse{
		Verified: true,
		Details:  details,
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
			return models.ImageMetadataResponse{}, fmt.Errorf("%w: %v", console_errors.ErrImageNotFound, err)

		} else if isAuthError(err) {
			return models.ImageMetadataResponse{}, fmt.Errorf("%w: %v", console_errors.ErrArtifactAuthFailed, err)

		} else if isConnectionError(err) {
			return models.ImageMetadataResponse{}, fmt.Errorf("%w: %v", console_errors.ErrArtifactConnectionRefused, err)

		} else {
			return models.ImageMetadataResponse{}, fmt.Errorf("%w: %v", console_errors.ErrFetchImageMetadataFailed, err)
		}
	}

	// Fetch digest
	img, err := remote.Image(ref, opts...)
	if err != nil {
		return models.ImageMetadataResponse{}, fmt.Errorf("%w: %v", console_errors.ErrArtifactFailedToFetchImage, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return models.ImageMetadataResponse{}, fmt.Errorf("%w: %v", console_errors.ErrArtifactFailedToComputeDigest, err)
	}

	// Extract config metadata
	configFile, err := img.ConfigFile()
	if err != nil {
		return models.ImageMetadataResponse{}, fmt.Errorf("%w: %v", console_errors.ErrArtifactFailedToFetchConfig, err)
	}

	var createdTime *time.Time
	if !configFile.Created.IsZero() {
		createdTime = &configFile.Created.Time
	}

	labels := configFile.Config.Labels
	if len(labels) == 0 {
		labels = nil
	}

	response := models.ImageMetadataResponse{
		Image: &image,
		Metadata: models.Metadata{
			MediaType: string(descriptor.MediaType),
			Size:      descriptor.Size,
			Created:   createdTime,
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
	return strings.Contains(strings.ToLower(err.Error()), "not found") ||
		strings.Contains(strings.ToLower(err.Error()), "404") ||
		strings.Contains(strings.ToLower(err.Error()), "name unknown")
}

// isAuthError checks if the error indicates an authentication failure
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "unauthorized") ||
		strings.Contains(strings.ToLower(err.Error()), "401") ||
		strings.Contains(strings.ToLower(err.Error()), "authentication required")
}

// isConnectionError checks if the connection failed
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "connection refused")
}
