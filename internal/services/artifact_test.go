package services

import (
	"context"
	"strings"
	"testing"

	"github.com/securesign/rhtas-console/internal/models"
)

func strPtr(s string) *string { return &s }

func TestVerifyArtifactValidation(t *testing.T) {
	tests := []struct {
		name    string
		svc     *artifactService
		req     models.VerifyArtifactRequest
		wantErr string
	}{
		{
			name:    "empty OciImage",
			svc:     &artifactService{tufRepoURL: "https://tuf.example.com"},
			req:     models.VerifyArtifactRequest{},
			wantErr: "ociImage is a required parameter",
		},
		{
			name:    "empty TufRepoUrl with no service default",
			svc:     &artifactService{tufRepoURL: ""},
			req:     models.VerifyArtifactRequest{OciImage: "registry.example.com/image:latest"},
			wantErr: "tufRepoUrl is a required parameter",
		},
		{
			name: "empty TufRepoUrl in request overrides service default to empty",
			svc:  &artifactService{tufRepoURL: "https://tuf.example.com"},
			req: models.VerifyArtifactRequest{
				OciImage:   "registry.example.com/image:latest",
				TufRepoUrl: strPtr(""),
			},
			wantErr: "tufRepoUrl is a required parameter",
		},
		{
			name: "invalid OCI image reference with service default TUF",
			svc:  &artifactService{tufRepoURL: "https://tuf.example.com"},
			req: models.VerifyArtifactRequest{
				OciImage: "::::not a valid reference::::",
			},
			wantErr: "error getting signing layers",
		},
		{
			name: "invalid OCI image reference with all optional fields populated",
			svc:  &artifactService{tufRepoURL: ""},
			req: models.VerifyArtifactRequest{
				OciImage:                "::::not a valid reference::::",
				TufRepoUrl:              strPtr("https://tuf.example.com"),
				Bundle:                  &map[string]interface{}{"foo": "bar"},
				ExpectedOIDIssuer:       strPtr("https://issuer.example.com"),
				ExpectedOIDIssuerRegex:  strPtr(".*"),
				ExpectedSAN:             strPtr("user@example.com"),
				ExpectedSANRegex:        strPtr(".*"),
				ArtifactDigest:          strPtr("abc123"),
				ArtifactDigestAlgorithm: strPtr("sha512"),
				RequireTimestamp:        boolPtr(false),
				RequireCTLog:            boolPtr(false),
				RequireTLog:             boolPtr(false),
				PredicateType:           strPtr("https://slsa.dev/provenance/v1"),
			},
			wantErr: "error getting signing layers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.svc.VerifyArtifact(tt.req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }

func TestGetImageMetadataInvalidImage(t *testing.T) {
	svc := NewArtifactService("https://tuf.example.com")
	_, err := svc.GetImageMetadata(context.Background(), "::::not a valid reference::::", "", "")
	if err == nil {
		t.Fatal("expected error for invalid image reference")
	}
	if !strings.Contains(err.Error(), "invalid image URI") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "invalid image URI")
	}
}
