package errors

import (
	"testing"
)

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"ErrImageNotFound", ErrImageNotFound, "image not found"},
		{"ErrArtifactAuthFailed", ErrArtifactAuthFailed, "authentication failed"},
		{"ErrArtifactInvalidImageURI", ErrArtifactInvalidImageURI, "invalid image uri"},
		{"ErrArtifactFailedToFetchImage", ErrArtifactFailedToFetchImage, "failed to fetch image"},
		{"ErrArtifactFailedToComputeDigest", ErrArtifactFailedToComputeDigest, "failed to compute digest"},
		{"ErrArtifactFailedToFetchConfig", ErrArtifactFailedToFetchConfig, "failed to fetch config file"},
		{"ErrArtifactFailedToFetchSignatures", ErrArtifactFailedToFetchSignatures, "failed to fetch image cryptographic signatures"},
		{"ErrArtifactFailedToFetchAttestations", ErrArtifactFailedToFetchAttestations, "failed to fetch image signed attestations"},
		{"ErrArtifactConnectionRefused", ErrArtifactConnectionRefused, "connection refused"},
		{"ErrFetchImageMetadataFailed", ErrFetchImageMetadataFailed, "failed to fetch image metadata"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
