package services

import (
	"strings"
	"testing"

	"github.com/securesign/rhtas-console/internal/models"
)

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
			name: "empty TufRepoUrl in request but service has default",
			svc:  &artifactService{tufRepoURL: ""},
			req: models.VerifyArtifactRequest{
				OciImage: "registry.example.com/image:latest",
			},
			wantErr: "tufRepoUrl is a required parameter",
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
