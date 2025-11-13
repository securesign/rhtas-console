package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
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

	signatures, err := getImageSignaturesAndChains(digest, ref)
	if err != nil {
		return models.ImageMetadataResponse{}, fmt.Errorf("%w: %v", console_errors.ErrArtifactFailedToFetchSignatures, err)
	}

	attestationList, err := getImageAttestations(digest, ref)
	if err != nil {
		return models.ImageMetadataResponse{}, fmt.Errorf("%w: %v", console_errors.ErrArtifactFailedToFetchAttestations, err)
	}

	response := models.ImageMetadataResponse{
		Image: &image,
		Metadata: models.Metadata{
			MediaType: string(descriptor.MediaType),
			Size:      descriptor.Size,
			Created:   createdTime,
			Labels:    &labels,
		},
		Digest:       digest.String(),
		Signatures:   &signatures,
		Attestations: &attestationList,
	}
	return response, nil
}

// getImageSignaturesAndChains retrieves the list of unique cryptographic signatures and their corresponding certificate chains associated with the provided image digest.
func getImageSignaturesAndChains(imageDigest v1.Hash, ref name.Reference) (models.Signatures, error) {
	digest := ref.Context().Digest(imageDigest.String())
	h, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return models.Signatures{}, fmt.Errorf("error getting hash: %w", err)
	}
	// Construct the signature reference - sha256-<hash>.sig
	sigTag := digest.Context().Tag(fmt.Sprint(h.Algorithm, "-", h.Hex, ".sig"))
	// Get the manifest of the signature
	mf, err := crane.Manifest(sigTag.Name())
	if err != nil {
		// If manifest doesn't exist -> no signatures -> NOT an error
		if isManifestNotFound(err) {
			return models.Signatures{}, nil
		}
		// Other errors: network, auth, rate limit, etc.
		return nil, fmt.Errorf("error getting signature manifest: %w", err)
	}
	sigManifest, err := v1.ParseManifest(bytes.NewReader(mf))
	if err != nil {
		return models.Signatures{}, fmt.Errorf("error parsing signature manifest: %w", err)
	}
	signatures := models.Signatures{}
	// to track duplicates
	seenSigs := make(map[string]struct{})

	for _, layer := range sigManifest.Layers {
		digestStr := layer.Digest.String()
		certChain := ""
		if chain, ok := layer.Annotations["dev.sigstore.cosign/chain"]; ok && chain != "" {
			certChain = chain
		}
		chain := chainStringToArray(certChain)

		if _, exists := seenSigs[digestStr]; !exists {
			seenSigs[digestStr] = struct{}{}
			signature := models.Signature{
				Signature:        digestStr,
				CertificateChain: chain,
			}
			signatures = append(signatures, signature)

		}
	}
	return signatures, nil
}

// getImageAttestations returns the unique list of signed attestations associated with the imageDigest
func getImageAttestations(imageDigest v1.Hash, ref name.Reference) ([]string, error) {
	digest := ref.Context().Digest(imageDigest.String())
	h, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return nil, fmt.Errorf("error getting hash: %w", err)
	}
	// Construct the attestation reference - sha256-<hash>.att
	attTag := digest.Context().Tag(fmt.Sprint(h.Algorithm, "-", h.Hex, ".att"))
	// Get the manifest of the attestation
	mf, err := crane.Manifest(attTag.Name())
	if err != nil {
		// If manifest doesn't exist -> no attestations -> NOT an error
		if isManifestNotFound(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("error getting attestation manifest: %w", err)
	}
	sigManifest, err := v1.ParseManifest(bytes.NewReader(mf))
	if err != nil {
		return nil, fmt.Errorf("error parsing attestation manifest: %w", err)
	}
	attestationList := []string{}
	seen := make(map[string]struct{}) // to track attestation duplicates

	for _, layer := range sigManifest.Layers {
		digestStr := layer.Digest.String()
		if _, exists := seen[digestStr]; !exists {
			seen[digestStr] = struct{}{}
			attestationList = append(attestationList, digestStr)
		}
	}
	return attestationList, nil
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

// chainStringToArray splits a PEM certificate chain string into a slice of individual certificates.
func chainStringToArray(chain string) []string {
	chainList := []string{}
	parts := strings.SplitAfter(chain, "\n-----END CERTIFICATE-----")
	for _, cert := range parts {
		if strings.Contains(cert, "\n-----BEGIN") {
			cert = strings.ReplaceAll(cert, "\n-----BEGIN", "-----BEGIN")
		}
		if cert != "" {
			chainList = append(chainList, cert)
		}
	}
	return chainList
}

// isManifestNotFound detects "not found" errors from crane
func isManifestNotFound(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, "MANIFEST_UNKNOWN") ||
		strings.Contains(errMsg, "404") ||
		strings.Contains(errMsg, "not found") ||
		strings.Contains(errMsg, "unknown manifest")
}
