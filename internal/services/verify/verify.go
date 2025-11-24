package verify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/securesign/rhtas-console/internal/models"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"

	console_errors "github.com/securesign/rhtas-console/internal/errors"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

var (
	TufPublicGoodInstance = "https://tuf-repo-cdn.sigstore.dev"
)

// VerifyOptions defines configuration parameters for artifact verification.
type VerifyOptions struct {
	// OCIImage is the OCI image reference to verify.
	OCIImage string

	// full Sigstore verification bundle
	Bundle map[string]interface{}

	// ArtifactDigest is the hex-encoded digest of the artifact to verify.
	ArtifactDigest string

	// ArtifactDigestAlgorithm specifies the digest algorithm to use.
	// Default: "sha256"
	ArtifactDigestAlgorithm string

	// ExpectedOIDIssuer is the expected OIDC issuer for the signing certificate.
	ExpectedOIDIssuer string

	// ExpectedOIDIssuerRegex is a regular expression that the OIDC issuer must match.
	ExpectedOIDIssuerRegex string

	// ExpectedSAN is the expected identity (Subject Alternative Name) in the signing certificate.
	ExpectedSAN string

	// ExpectedSANRegex is a regular expression that the SAN value must match.
	ExpectedSANRegex string

	// RequireTimestamp ensures that either an RFC3161 signed timestamp or
	// a log entry integrated timestamp is present in the signature.
	// Default: true
	RequireTimestamp bool

	// RequireCTLog requires that a Certificate Transparency log entry exists
	// for the signing certificate.
	// Default: true
	RequireCTLog bool

	// RequireTLog requires that an Artifact Transparency log (Rekor) entry exists
	// for the verified artifact.
	// Default: true
	RequireTLog bool

	// MinBundleVersion specifies the minimum acceptable bundle version, e.g., "0.1".
	MinBundleVersion string

	// TrustedPublicKey is the path to a trusted public key for verification.
	TrustedPublicKey string

	// TrustedRootJSONPath is the path to a trusted root JSON file containing
	// trusted certificates and public keys.
	TrustedRootJSONPath string

	// TUFRootURL is the URL of the TUF repository containing the trusted root JSON file.
	TUFRootURL string

	// TUFTrustedRoot is the path to the trusted TUF root.json file
	// used to bootstrap trust in the remote TUF repository.
	TUFTrustedRoot string

	// PredicateType specifies the type of the predicate for the attestation.
	PredicateType string
}

func NewVerifyOptions() VerifyOptions {
	return VerifyOptions{
		RequireTimestamp:        true,
		RequireCTLog:            true,
		RequireTLog:             true,
		ArtifactDigestAlgorithm: "sha256",
		ExpectedOIDIssuerRegex:  ".*",
	}
}

func VerifyArtifact(verifyOpts VerifyOptions) (verifyArtifactResponse models.VerifyArtifactResponse, err error) {

	// SignatureViews
	// loop over all signing layers
	verifyArtifactResponse = models.VerifyArtifactResponse{}
	signingLayers, err := signingLayersFromOCIImage(verifyOpts.OCIImage)
	if err != nil {
		return models.VerifyArtifactResponse{}, fmt.Errorf("error getting signing layers: %w", err)
	}

	signingLayerId := 0
	var signingIdentities []models.ArtifactIdentity
	var sigDetails models.SignatureView
	for _, layer := range signingLayers {
		sigDetails, signingIdentities, err = VerifyAndGetSignatureView(verifyOpts, layer)
		sigDetails.Id = signingLayerId
		signingLayerId++
		if err != nil {
			return models.VerifyArtifactResponse{}, fmt.Errorf("error verifying signing layer: %w", err)
		}
		verifyArtifactResponse.Signatures = append(verifyArtifactResponse.Signatures, sigDetails)
	}

	// AttestationViews
	// loop over all attestation layers
	attestationLayers, err := attestationLayersFromOCIImage(verifyOpts.OCIImage)
	if err != nil {
		return models.VerifyArtifactResponse{}, fmt.Errorf("error getting attestation layers: %w", err)
	}
	attestationLayerId := 0
	var attestationIdentities []models.ArtifactIdentity
	var attDetails models.AttestationView
	for _, layer := range attestationLayers {
		attDetails, attestationIdentities, err = VerifyAndGetAttestationView(verifyOpts, layer)
		attDetails.Id = attestationLayerId
		attestationLayerId++
		if err != nil {
			return models.VerifyArtifactResponse{}, fmt.Errorf("error verifying signing layer: %w", err)
		}
		verifyArtifactResponse.Attestations = append(verifyArtifactResponse.Attestations, attDetails)
	}

	// Summary
	verifyArtifactResponse.Summary.SignatureCount = len(verifyArtifactResponse.Signatures)
	verifyArtifactResponse.Summary.AttestationCount = len(verifyArtifactResponse.Attestations)
	verifyArtifactResponse.Summary.RekorEntryCount = verifyArtifactResponse.Summary.SignatureCount + verifyArtifactResponse.Summary.AttestationCount

	// ImageMetadataResponse
	// Add artifact metadata
	artifactMetadata, err := GetImageMetadata(verifyOpts.OCIImage, "", "")
	if err != nil {
		return models.VerifyArtifactResponse{}, fmt.Errorf("error getting artifact metadata: %w", err)
	}
	verifyArtifactResponse.Artifact = artifactMetadata

	// Identities
	identities := append(signingIdentities, attestationIdentities...)
	verifyArtifactResponse.Summary.Identities = dedupeIdentities(identities)

	// TimeCoherenceSummary
	timeCoherenceSummary := ComputeTimeCoherenceSummary(verifyArtifactResponse)
	verifyArtifactResponse.Summary.TimeCoherence = &timeCoherenceSummary

	return verifyArtifactResponse, nil
}

func VerifyLayer(verifyOpts VerifyOptions, b *bundle.Bundle) (verified bool, verificationResult *verify.VerificationResult, err error) {
	if verifyOpts.MinBundleVersion != "" {
		if !b.MinVersion(verifyOpts.MinBundleVersion) {
			return false, nil, fmt.Errorf("bundle is not of minimum version %s", verifyOpts.MinBundleVersion)
		}
	}

	verifierConfig := []verify.VerifierOption{}
	identityPolicies := []verify.PolicyOption{}
	var artifactPolicy verify.ArtifactPolicyOption

	if verifyOpts.RequireCTLog {
		verifierConfig = append(verifierConfig, verify.WithSignedCertificateTimestamps(1))
	}

	if verifyOpts.RequireTimestamp {
		verifierConfig = append(verifierConfig, verify.WithObserverTimestamps(1))
	}

	if verifyOpts.RequireTLog {
		verifierConfig = append(verifierConfig, verify.WithTransparencyLog(1))
	}

	if verifyOpts.TrustedPublicKey == "" {
		certID, err := verify.NewShortCertificateIdentity(verifyOpts.ExpectedOIDIssuer, verifyOpts.ExpectedOIDIssuerRegex, verifyOpts.ExpectedSAN, verifyOpts.ExpectedSANRegex)
		if err != nil {
			return false, nil, err
		}
		identityPolicies = append(identityPolicies, verify.WithCertificateIdentity(certID))
	} else {
		identityPolicies = append(identityPolicies, verify.WithKey())
	}

	var trustedMaterial = make(root.TrustedMaterialCollection, 0)
	var trustedRootJSON []byte

	if verifyOpts.TUFRootURL != "" {
		opts := tuf.DefaultOptions()
		opts.RepositoryBaseURL = verifyOpts.TUFRootURL
		if !urlsEqual(opts.RepositoryBaseURL, TufPublicGoodInstance) {
			if err := setOptsRoot(opts); err != nil {
				return false, nil, fmt.Errorf("failed to set root in options for %s: %w", verifyOpts.TUFRootURL, err)
			}
		}
		fetcher := fetcher.NewDefaultFetcher()
		fetcher.SetHTTPUserAgent(util.ConstructUserAgent())
		opts.Fetcher = fetcher

		// Load the tuf root.json if provided, if not use public good
		if verifyOpts.TUFTrustedRoot != "" {
			rb, err := os.ReadFile(verifyOpts.TUFTrustedRoot)
			if err != nil {
				return false, nil, fmt.Errorf("failed to read %s: %w",
					verifyOpts.TUFTrustedRoot, err)
			}
			opts.Root = rb
		}

		client, err := tuf.New(opts)
		if err != nil {
			return false, nil, err
		}
		trustedRootJSON, err = client.GetTarget("trusted_root.json")
		if err != nil {
			return false, nil, err
		}
	} else if verifyOpts.TrustedRootJSONPath != "" {
		trustedRootJSON, err = os.ReadFile(verifyOpts.TrustedRootJSONPath)
		if err != nil {
			return false, nil, fmt.Errorf("failed to read %s: %w",
				verifyOpts.TrustedRootJSONPath, err)
		}
	}

	if len(trustedRootJSON) > 0 {
		var trustedRoot *root.TrustedRoot
		trustedRoot, err = root.NewTrustedRootFromJSON(trustedRootJSON)
		if err != nil {
			return false, nil, err
		}
		trustedMaterial = append(trustedMaterial, trustedRoot)
	}
	if verifyOpts.TrustedPublicKey != "" {
		pemBytes, err := os.ReadFile(verifyOpts.TrustedPublicKey)
		if err != nil {
			return false, nil, err
		}
		pemBlock, _ := pem.Decode(pemBytes)
		if pemBlock == nil {
			return false, nil, errors.New("failed to decode pem block")
		}
		pubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return false, nil, err
		}
		trustedMaterial = append(trustedMaterial, trustedPublicKeyMaterial(pubKey))
	}

	if len(trustedMaterial) == 0 {
		return false, nil, errors.New("no trusted material provided")
	}

	sev, err := verify.NewVerifier(trustedMaterial, verifierConfig...)
	if err != nil {
		return false, nil, err
	}

	if verifyOpts.ArtifactDigest != "" { //nolint:gocritic
		artifactDigestBytes, err := hex.DecodeString(verifyOpts.ArtifactDigest)
		if err != nil {
			return false, nil, err
		}
		artifactPolicy = verify.WithArtifactDigest(verifyOpts.ArtifactDigestAlgorithm, artifactDigestBytes)
	} else {
		artifactPolicy = verify.WithoutArtifactUnsafe()
		fmt.Fprintf(os.Stderr, "No artifact provided, skipping artifact verification. This is unsafe!\n")
	}

	verificationResult, err = sev.Verify(b, verify.NewPolicy(artifactPolicy, identityPolicies...))
	if err != nil {
		return false, nil, err
	}
	return true, verificationResult, nil
}

func VerifyAndGetSignatureView(verifyOpts VerifyOptions, layer *v1.Descriptor) (signatureView models.SignatureView, identities []models.ArtifactIdentity, err error) {
	var b *bundle.Bundle
	invalidSignatureView := models.SignatureView{SignatureStatus: "invalid"}

	b, verifyOpts.ArtifactDigest, err = bundleFromSigningLayer(layer, verifyOpts.RequireTLog, verifyOpts.RequireTimestamp)
	if err != nil {
		return invalidSignatureView, []models.ArtifactIdentity{}, fmt.Errorf("failed to extract bundle from signing layer %w", err)
	}

	signatureView, identities, err = extractSignatureViewFromLayer(layer, b)
	if err != nil {
		return invalidSignatureView, []models.ArtifactIdentity{}, fmt.Errorf("failed to extract SignatureView from layer %w", err)
	}

	if len(signatureView.SigningCertificate.Sans) == 0 {
		return invalidSignatureView, []models.ArtifactIdentity{}, fmt.Errorf("signing certificate contains no SANs")
	}
	verifyOpts.ExpectedSAN = signatureView.SigningCertificate.Sans[0]

	verified, _, err := VerifyLayer(verifyOpts, b)
	if err != nil && !verified {
		return invalidSignatureView, []models.ArtifactIdentity{}, fmt.Errorf("failed to verify signing layer: %w", err)
	}

	signatureView.SignatureStatus = "verified"
	return signatureView, identities, nil
}

func VerifyAndGetAttestationView(verifyOpts VerifyOptions, layer *v1.Descriptor) (attestationView models.AttestationView, identities []models.ArtifactIdentity, err error) {
	var b *bundle.Bundle
	invalidAttestationView := models.AttestationView{AttestationStatus: "invalid"}

	b, verifyOpts.ArtifactDigest, err = bundleFromAttestationLayer(verifyOpts.OCIImage, layer, verifyOpts.RequireTLog, verifyOpts.RequireTimestamp)
	if err != nil {
		return invalidAttestationView, []models.ArtifactIdentity{}, fmt.Errorf("failed to get bundle from attestation layer: %w", err)
	}

	attestationView, identities, err = extractAttestationViewFromLayer(layer, b)
	if err != nil {
		return invalidAttestationView, []models.ArtifactIdentity{}, fmt.Errorf("failed to extract AttestationView from layer: %w", err)
	}
	// Get SAN from attestation signing certificate
	signingCertificate := ""
	if certificate, ok := layer.Annotations["dev.sigstore.cosign/certificate"]; ok && certificate != "" {
		signingCertificate = certificate
	} else {
		return invalidAttestationView, []models.ArtifactIdentity{}, errors.New("missing signing certificate annotation 'dev.sigstore.cosign/certificate'")
	}
	san, err := getSANFromCert(signingCertificate)
	if err != nil {
		return invalidAttestationView, []models.ArtifactIdentity{}, fmt.Errorf("error getting SAN from signing certificate: %w", err)
	}
	verifyOpts.ExpectedSAN = san

	verified, verificationResult, err := VerifyLayer(verifyOpts, b)
	if err != nil && !verified {
		return invalidAttestationView, []models.ArtifactIdentity{}, fmt.Errorf("failed to verify attestation layer: %w", err)
	}

	// Add remaining fields
	attestationView.PredicateType = verificationResult.Statement.PredicateType
	attestationView.Type = verificationResult.Statement.Type
	statementBytes, err := json.MarshalIndent(verificationResult.Statement, "", "  ")
	if err != nil {
		return models.AttestationView{}, []models.ArtifactIdentity{}, fmt.Errorf("failed to marshal statement: %w", err)
	}

	attestationView.RawStatementJson = string(statementBytes)
	attestationView.AttestationStatus = "verified"

	return attestationView, identities, nil
}

// GetImageMetadata return the OCI image metadata
func GetImageMetadata(image string, username string, password string) (models.ImageMetadataResponse, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return models.ImageMetadataResponse{}, fmt.Errorf("invalid image URI: %w", err)
	}

	auth := authn.Anonymous
	if username != "" && password != "" {
		auth = &authn.Basic{Username: username, Password: password}
	}

	opts := []remote.Option{remote.WithAuth(auth)}

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

// extractSignatureViewFromLayer extracts the SignatureView from signing layer
func extractSignatureViewFromLayer(layer *v1.Descriptor, b *bundle.Bundle) (signatureView models.SignatureView, identities []models.ArtifactIdentity, err error) {

	if b == nil {
		return models.SignatureView{}, []models.ArtifactIdentity{}, fmt.Errorf("empty bundle")
	}

	certChain := ""
	if chain, ok := layer.Annotations["dev.sigstore.cosign/chain"]; ok && chain != "" {
		certChain = chain
	}

	var parsedCerts []models.ParsedCertificate

	if certChain != "" {
		chainCerts, err := parsePEMCertificates(certChain)
		if err != nil {
			return models.SignatureView{}, []models.ArtifactIdentity{}, fmt.Errorf("failed parsing certificate chain: %w", err)
		}

		for _, c := range chainCerts {
			sn := c.Cert.SerialNumber.String()
			role := identifyCertRole(c.Cert)
			sanList := mergeSANs(c.Cert)
			pc := models.ParsedCertificate{
				Role:         role,
				Subject:      c.Cert.Subject.String(),
				Issuer:       c.Cert.Issuer.String(),
				NotBefore:    c.Cert.NotBefore.UTC(),
				NotAfter:     c.Cert.NotAfter.UTC(),
				Sans:         sanList,
				SerialNumber: &sn,
				IsCa:         c.Cert.IsCA,
				Pem:          c.PEM,
			}

			parsedCerts = append(parsedCerts, pc)
		}
	}

	// SigningCertificate
	var signingCertStr string
	if cert, ok := layer.Annotations["dev.sigstore.cosign/certificate"]; ok && cert != "" {
		signingCertStr = cert
	}

	certs, err := parsePEMCertificates(signingCertStr)
	if err != nil {
		return models.SignatureView{}, []models.ArtifactIdentity{}, fmt.Errorf("failed parsing signing certificate: %w", err)
	}
	if len(certs) == 0 {
		return models.SignatureView{}, []models.ArtifactIdentity{}, fmt.Errorf("no signing certificate found in annotations")
	}
	c := certs[0]
	sanList := mergeSANs(c.Cert)
	sn := c.Cert.SerialNumber.String()
	parsedSigningCert := models.ParsedCertificate{
		Role:         models.CertificateRoleLeaf,
		Subject:      c.Cert.Subject.String(),
		Issuer:       c.Cert.Issuer.String(),
		NotBefore:    c.Cert.NotBefore.UTC(),
		NotAfter:     c.Cert.NotAfter.UTC(),
		Sans:         sanList,
		SerialNumber: &sn,
		IsCa:         c.Cert.IsCA,
		Pem:          c.PEM,
	}

	// Rekor entries
	tlogEntries := b.VerificationMaterial.TlogEntries
	var tlogMap map[string]interface{}
	if len(tlogEntries) > 0 && tlogEntries[0] != nil {
		raw, err := json.Marshal(tlogEntries[0])
		if err != nil {
			return models.SignatureView{}, []models.ArtifactIdentity{}, fmt.Errorf("failed to marshal tlog entry: %w", err)
		}
		if err := json.Unmarshal(raw, &tlogMap); err != nil {
			return models.SignatureView{}, []models.ArtifactIdentity{}, fmt.Errorf("failed to unmarshal tlog entry: %w", err)
		}
	} else {
		return models.SignatureView{}, []models.ArtifactIdentity{}, fmt.Errorf("bundle contains no Rekor entries")
	}

	var rawBundle string
	if b != nil {
		jb, err := json.MarshalIndent(b, "", "  ")
		if err != nil {
			return models.SignatureView{}, []models.ArtifactIdentity{}, fmt.Errorf("failed to marshal bundle: %w", err)
		}
		rawBundle = string(jb)
	}

	var isoTime *time.Time
	t := time.Unix(tlogEntries[0].IntegratedTime, 0).UTC()
	isoTime = &t

	digestStr := layer.Digest.String()
	signatureView = models.SignatureView{
		Digest:             digestStr,
		CertificateChain:   parsedCerts,
		SigningCertificate: parsedSigningCert,
		TlogEntry:          tlogMap,
		RawBundleJson:      rawBundle,
		Timestamp:          isoTime,
	}

	// SAN identities with correct type classification
	issuer := c.Cert.Issuer.String()
	for _, san := range sanList {
		identities = append(identities, models.ArtifactIdentity{
			Source: models.San,
			Type:   classifyIdentity(san),
			Value:  san,
			Issuer: &issuer,
		})
	}

	return signatureView, identities, nil
}

// extractAttestationViewFromLayer extracts the AttestationView from attestation layer
func extractAttestationViewFromLayer(layer *v1.Descriptor, b *bundle.Bundle) (attestationView models.AttestationView, identities []models.ArtifactIdentity, err error) {

	if b == nil {
		return models.AttestationView{}, []models.ArtifactIdentity{}, fmt.Errorf("empty bundle")
	}

	// Tlog entry
	tlogEntries := b.VerificationMaterial.TlogEntries
	var tlogMap map[string]interface{}
	if len(tlogEntries) > 0 && tlogEntries[0] != nil {
		raw, err := json.Marshal(tlogEntries[0])
		if err != nil {
			return models.AttestationView{}, []models.ArtifactIdentity{}, fmt.Errorf("failed to marshal tlog entry: %w", err)
		}
		if err := json.Unmarshal(raw, &tlogMap); err != nil {
			return models.AttestationView{}, []models.ArtifactIdentity{}, fmt.Errorf("failed to unmarshal tlog entry: %w", err)
		}
	} else {
		return models.AttestationView{}, []models.ArtifactIdentity{}, fmt.Errorf("bundle contains no Rekor entries")
	}

	// Raw bunle
	var rawBundle string
	if b != nil {
		jb, err := json.MarshalIndent(b, "", "  ")
		if err != nil {
			return models.AttestationView{}, []models.ArtifactIdentity{}, fmt.Errorf("failed to marshal bundle: %w", err)
		}
		rawBundle = string(jb)
	}

	// Timestamp
	var isoTime *time.Time
	t := time.Unix(tlogEntries[0].IntegratedTime, 0).UTC()
	isoTime = &t

	digestStr := layer.Digest.String()
	attestationView = models.AttestationView{
		Digest:        digestStr,
		TlogEntry:     tlogMap,
		RawBundleJson: rawBundle,
		Timestamp:     isoTime,
	}

	// Extract identities from signing certificate
	signingCertificate := ""
	if certStr, ok := layer.Annotations["dev.sigstore.cosign/certificate"]; ok && certStr != "" {
		signingCertificate = certStr
	}

	certs, err := parsePEMCertificates(signingCertificate)
	if err != nil {
		return attestationView, []models.ArtifactIdentity{}, fmt.Errorf("failed parsing signing certificate: %w", err)
	}
	if len(certs) > 0 {
		c := certs[0]
		issuer := c.Cert.Issuer.String()
		sanList := mergeSANs(c.Cert)

		// SAN identities
		for _, san := range sanList {
			identities = append(identities, models.ArtifactIdentity{
				Source: models.San,
				Type:   classifyIdentity(san),
				Value:  san,
				Issuer: &issuer,
			})
		}
	}

	return attestationView, identities, nil
}

type nonExpiringVerifier struct {
	signature.Verifier
}

func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool {
	return true
}

func trustedPublicKeyMaterial(pk crypto.PublicKey) *root.TrustedPublicKeyMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		pkECDSA, ok := pk.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("trustedPublicKeyMaterial: expected *ecdsa.PublicKey, got %T", pk)
		}
		verifier, err := signature.LoadECDSAVerifier(pkECDSA, crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return &nonExpiringVerifier{verifier}, nil
	})
}

// bundleFromSigningLayer returns a Bundle based on signing layer (based on OCI image reference)
func bundleFromSigningLayer(layer *v1.Descriptor, hasTlog, hasTimestamp bool) (*bundle.Bundle, string, error) {
	// 1. Build the verification material for the bundle
	verificationMaterial, err := getBundleVerificationMaterial(layer, hasTlog, hasTimestamp)
	if err != nil {
		return nil, "", fmt.Errorf("error getting verification material: %w", err)
	}
	// 2. Build the message signature for the bundle
	msgSignature, err := getBundleMsgSignature(layer)
	if err != nil {
		return nil, "", fmt.Errorf("error getting message signature: %w", err)
	}
	// 3. Construct and verify the bundle
	bundleMediaType, err := bundle.MediaTypeString("0.1")
	if err != nil {
		return nil, "", fmt.Errorf("error getting bundle media type: %w", err)
	}
	pb := protobundle.Bundle{
		MediaType:            bundleMediaType,
		VerificationMaterial: verificationMaterial,
		Content:              msgSignature,
	}
	bun, err := bundle.NewBundle(&pb)
	if err != nil {
		return nil, "", fmt.Errorf("error creating bundle: %w", err)
	}
	// 4. Return the bundle and the digest of the simple signing layer (this is what is signed)
	return bun, layer.Digest.Hex, nil
}

// signingLayersFromOCIImage returns the signing layers from the OCI image reference
func signingLayersFromOCIImage(imageRef string) ([]*v1.Descriptor, error) {
	// 1. Get the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("error parsing image reference: %w", err)
	}
	// 2. Get the image descriptor
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("error getting image descriptor: %w", err)
	}
	// 3. Get the digest
	digest := ref.Context().Digest(desc.Digest.String())
	h, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return nil, fmt.Errorf("error getting hash: %w", err)
	}
	// 4. Construct the signature reference - sha256-<hash>.sig
	sigTag := digest.Context().Tag(fmt.Sprint(h.Algorithm, "-", h.Hex, ".sig"))
	// 5. Get the manifest of the signature
	mf, err := crane.Manifest(sigTag.Name())
	if err != nil {
		// --- Detect "manifest unknown" and return empty signatures ---
		var terr *transport.Error
		if errors.As(err, &terr) {
			if terr.StatusCode == 404 || terr.Errors[0].Code == transport.ManifestUnknownErrorCode {
				// No signature exists: not an error
				return []*v1.Descriptor{}, nil
			}
		}

		return nil, fmt.Errorf("error getting signature manifest: %w", err)
	}

	sigManifest, err := v1.ParseManifest(bytes.NewReader(mf))
	if err != nil {
		return nil, fmt.Errorf("error parsing signature manifest: %w", err)
	}
	// 6. Ensure there is at least one layer and it is a simple signing layer
	if len(sigManifest.Layers) == 0 || sigManifest.Layers[0].MediaType != "application/vnd.dev.cosign.simplesigning.v1+json" {
		return nil, fmt.Errorf("no suitable layers found in signature manifest")
	}
	// 7. Convert []Descriptor to []*Descriptor
	layers := make([]*v1.Descriptor, 0, len(sigManifest.Layers))
	for i := range sigManifest.Layers {
		d := sigManifest.Layers[i]
		layers = append(layers, &d)
	}
	// 8. Return the layers
	return layers, nil
}

// getBundleVerificationMaterial returns the bundle verification material from the simple signing layer
func getBundleVerificationMaterial(manifestLayer *v1.Descriptor, hasTlog, hasTimestamp bool) (*protobundle.VerificationMaterial, error) {
	// 1. Get the signing certificate chain
	signingCert, err := getVerificationMaterialX509CertificateChain(manifestLayer)
	if err != nil {
		return nil, fmt.Errorf("error getting signing certificate: %w", err)
	}
	// 2. Get the transparency log entries
	var tlogEntries []*protorekor.TransparencyLogEntry
	if hasTlog {
		tlogEntries, err = getVerificationMaterialTlogEntries(manifestLayer)
		if err != nil {
			return nil, fmt.Errorf("error getting tlog entries: %w", err)
		}
	}
	var timestampEntries *protobundle.TimestampVerificationData
	if hasTimestamp {
		// Try RFC3161 timestamp first
		timestampEntries, err = getVerificationMaterialTimestampEntries(manifestLayer)
		if err != nil {
			// If no RFC3161 timestamp exists, fall back to Rekor integrated timestamp
			// (which is already represented in TlogEntries)
			fmt.Fprintf(os.Stderr, "No RFC3161 timestamp found, relying on Rekor integrated timestamp.\n")
			timestampEntries = nil
		}
	}
	// 3. Construct the verification material
	return &protobundle.VerificationMaterial{
		Content:                   signingCert,
		TlogEntries:               tlogEntries,
		TimestampVerificationData: timestampEntries,
	}, nil
}

// getVerificationMaterialTlogEntries returns the verification material transparency log entries from the simple signing layer
func getVerificationMaterialTlogEntries(manifestLayer *v1.Descriptor) ([]*protorekor.TransparencyLogEntry, error) {
	// 1. Get the bundle annotation
	bun, ok := manifestLayer.Annotations["dev.sigstore.cosign/bundle"]
	if !ok || bun == "" {
		return nil, fmt.Errorf("missing or empty bundle annotation")
	}
	var jsonData map[string]interface{}
	err := json.Unmarshal([]byte(bun), &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}

	// 2. Get the log index, log ID, integrated time, signed entry timestamp and body
	payloadVal, ok := jsonData["Payload"]
	if !ok {
		return nil, fmt.Errorf("missing Payload in bundle JSON")
	}
	payload, ok := payloadVal.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid type for Payload (expected object, got %T)", payloadVal)
	}
	logIndex, ok := payload["logIndex"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting logIndex")
	}
	li, ok := payload["logID"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting logID")
	}
	logID, err := hex.DecodeString(li)
	if err != nil {
		return nil, fmt.Errorf("error decoding logID: %w", err)
	}
	integratedTime, ok := payload["integratedTime"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting integratedTime")
	}
	set, ok := jsonData["SignedEntryTimestamp"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting SignedEntryTimestamp")
	}
	signedEntryTimestamp, err := base64.StdEncoding.DecodeString(set)
	if err != nil {
		return nil, fmt.Errorf("error decoding signedEntryTimestamp: %w", err)
	}
	// 3. Unmarshal the body and extract the rekor KindVersion details
	body, ok := payload["body"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting body")
	}
	bodyBytes, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("error decoding body: %w", err)
	}
	err = json.Unmarshal(bodyBytes, &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}
	apiVersion, ok := jsonData["apiVersion"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting apiVersion")
	}

	kind, ok := jsonData["kind"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting kind")
	}
	// 4. Construct the transparency log entry list
	return []*protorekor.TransparencyLogEntry{
		{
			LogIndex: int64(logIndex),
			LogId: &protocommon.LogId{
				KeyId: logID,
			},
			KindVersion: &protorekor.KindVersion{
				Kind:    kind,
				Version: apiVersion,
			},
			IntegratedTime: int64(integratedTime),
			InclusionPromise: &protorekor.InclusionPromise{
				SignedEntryTimestamp: signedEntryTimestamp,
			},
			InclusionProof:    nil,
			CanonicalizedBody: bodyBytes,
		},
	}, nil
}

func getVerificationMaterialTimestampEntries(manifestLayer *v1.Descriptor) (*protobundle.TimestampVerificationData, error) {
	// 1. Get the bundle annotation
	ts := manifestLayer.Annotations["dev.sigstore.cosign/rfc3161timestamp"]
	// 2. Get the key/value pairs maps
	var keyValPairs map[string]string
	err := json.Unmarshal([]byte(ts), &keyValPairs)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON blob into key/val map: %w", err)
	}
	// 3. Verify the key "SignedRFC3161Timestamp" is present
	if _, ok := keyValPairs["SignedRFC3161Timestamp"]; !ok {
		return nil, errors.New("error getting SignedRFC3161Timestamp from key/value pairs")
	}
	// 4. Decode the base64 encoded timestamp
	der, err := base64.StdEncoding.DecodeString(keyValPairs["SignedRFC3161Timestamp"])
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 encoded timestamp: %w", err)
	}
	// 4. Construct the timestamp entry list
	return &protobundle.TimestampVerificationData{
		Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
			{
				SignedTimestamp: der,
			},
		},
	}, nil
}

// getVerificationMaterialX509CertificateChain returns the verification material X509 certificate chain from the simple signing layer
func getVerificationMaterialX509CertificateChain(manifestLayer *v1.Descriptor) (*protobundle.VerificationMaterial_X509CertificateChain, error) {
	// 1. Get the PEM certificate from the simple signing layer
	pemCert := manifestLayer.Annotations["dev.sigstore.cosign/certificate"]
	// 2. Construct the DER encoded version of the PEM certificate
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	signingCert := protocommon.X509Certificate{
		RawBytes: block.Bytes,
	}
	// 3. Construct the X509 certificate chain
	return &protobundle.VerificationMaterial_X509CertificateChain{
		X509CertificateChain: &protocommon.X509CertificateChain{
			Certificates: []*protocommon.X509Certificate{&signingCert},
		},
	}, nil
}

// getBundleMsgSignature returns the bundle message signature from the simple signing layer
func getBundleMsgSignature(simpleSigningLayer *v1.Descriptor) (*protobundle.Bundle_MessageSignature, error) {
	// 1. Get the message digest algorithm
	var msgHashAlg protocommon.HashAlgorithm
	switch simpleSigningLayer.Digest.Algorithm {
	case "sha256":
		msgHashAlg = protocommon.HashAlgorithm_SHA2_256
	default:
		return nil, fmt.Errorf("unknown digest algorithm: %s", simpleSigningLayer.Digest.Algorithm)
	}
	// 2. Get the message digest
	digest, err := hex.DecodeString(simpleSigningLayer.Digest.Hex)
	if err != nil {
		return nil, fmt.Errorf("error decoding digest: %w", err)
	}
	// 3. Get the signature
	s := simpleSigningLayer.Annotations["dev.cosignproject.cosign/signature"]
	sig, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("error decoding manSig: %w", err)
	}
	// Construct the bundle message signature
	return &protobundle.Bundle_MessageSignature{
		MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: msgHashAlg,
				Digest:    digest,
			},
			Signature: sig,
		},
	}, nil
}

// setOptsRoot fetches the root.json from the repository and sets it in the options.
func setOptsRoot(opts *tuf.Options) error {
	rootURL := opts.RepositoryBaseURL + "/root.json"
	resp, err := http.Get(rootURL)
	if err != nil {
		return fmt.Errorf("failed to fetch root.json: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("failed to close resp Body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch root.json: received status %d", resp.StatusCode)
	}

	rootData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read root.json: %w", err)
	}
	opts.Root = rootData
	return nil
}

// urlsEqual compares two URLs for logical equivalence, ignoring trailing slashes.
func urlsEqual(a, b string) bool {
	ua, err1 := url.Parse(strings.TrimRight(a, "/"))
	ub, err2 := url.Parse(strings.TrimRight(b, "/"))
	return err1 == nil && err2 == nil && ua.String() == ub.String()
}

// bundleFromAttestationLayer returns a Bundle for attestation layer
func bundleFromAttestationLayer(imageRef string, attestationLayer *v1.Descriptor, hasTlog, hasTimestamp bool) (*bundle.Bundle, string, error) {

	verificationMaterial, err := getBundleVerificationMaterial(attestationLayer, hasTlog, hasTimestamp)
	if err != nil {
		return nil, "", fmt.Errorf("error getting verification material: %w", err)
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, "", fmt.Errorf("error parsing reference: %w", err)
	}

	repoName := ref.Context().Name()
	dsseEnvelope, err := getBundleDSSEEnvelope(repoName, attestationLayer)
	if err != nil {
		return nil, "", fmt.Errorf("error getting DSSE envelope: %w", err)
	}

	subjectDigest, err := getSubjectDigestFromDSSE(dsseEnvelope)
	if err != nil {
		return nil, "", fmt.Errorf("error getting subject digest: %w", err)
	}

	// Construct and verify the bundle
	bundleMediaType, err := bundle.MediaTypeString("0.1")
	if err != nil {
		return nil, "", fmt.Errorf("error getting bundle media type: %w", err)
	}

	pb := protobundle.Bundle{
		MediaType:            bundleMediaType,
		VerificationMaterial: verificationMaterial,
		Content:              dsseEnvelope,
	}

	bun, err := bundle.NewBundle(&pb)
	if err != nil {
		return nil, "", fmt.Errorf("error creating bundle: %w", err)
	}

	return bun, subjectDigest, nil
}

// attestationLayersFromOCIImage returns the attestation layer from signing layer
func attestationLayersFromOCIImage(imageRef string) ([]*v1.Descriptor, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("error parsing image reference: %w", err)
	}

	desc, err := remote.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("error getting image descriptor: %w", err)
	}

	digest := ref.Context().Digest(desc.Digest.String())
	h, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return nil, fmt.Errorf("error getting hash: %w", err)
	}

	// Construct the attestation reference - sha256-<hash>.att
	attTag := digest.Context().Tag(fmt.Sprint(h.Algorithm, "-", h.Hex, ".att"))

	// Get the manifest of the attestation
	mf, err := crane.Manifest(attTag.Name())
	if err != nil {
		// --- Detect "manifest unknown" and return empty list ---
		var terr *transport.Error
		if errors.As(err, &terr) {
			if terr.StatusCode == 404 || terr.Errors[0].Code == transport.ManifestUnknownErrorCode {
				// No attestation exists: not an error
				return []*v1.Descriptor{}, nil
			}
		}

		return nil, fmt.Errorf("error getting attestation manifest: %w", err)
	}

	attManifest, err := v1.ParseManifest(bytes.NewReader(mf))
	if err != nil {
		return nil, fmt.Errorf("error parsing attestation manifest: %w", err)
	}

	// Ensure there is at least one layer with DSSE media type
	if len(attManifest.Layers) == 0 {
		return nil, fmt.Errorf("no layers found in attestation manifest")
	}

	// Look for only DSSE attestation layer (only supported layers)
	layers := []*v1.Descriptor{}
	for i := range attManifest.Layers {
		layer := &attManifest.Layers[i]
		if layer.MediaType == "application/vnd.dsse.envelope.v1+json" {
			layers = append(layers, layer)
		}
	}

	if len(layers) == 0 {
		return nil, fmt.Errorf("no DSSE attestation layers found")
	}

	return layers, nil
}

// getBundleDSSEEnvelope returns the bundle DSSE envelope from the attestation layer
func getBundleDSSEEnvelope(repoName string, attestationLayer *v1.Descriptor) (*protobundle.Bundle_DsseEnvelope, error) {
	digestRef, err := name.NewDigest(fmt.Sprintf("%s@%s", repoName, attestationLayer.Digest.String()))
	if err != nil {
		return nil, fmt.Errorf("error parsing digest reference: %w", err)
	}

	// Fetch the attestation layer blob
	layer, err := remote.Layer(digestRef)
	if err != nil {
		return nil, fmt.Errorf("error fetching attestation layer blob: %w", err)
	}

	reader, err := layer.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("error reading layer content: %w", err)
	}
	defer func() {
		if cerr := reader.Close(); cerr != nil {
			log.Printf("failed to close reader: %v", cerr)
		}
	}()

	payloadBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading attestation payload: %w", err)
	}

	// Build DSSE envelope from payload
	var envelope protodsse.Envelope
	err = json.Unmarshal(payloadBytes, &envelope)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling DSSE envelope from payloadBytes: %w", err)
	}

	return &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &envelope}, nil
}

// getSubjectDigestFromDSSE extracts the subject digest from the DSSE payload
func getSubjectDigestFromDSSE(dsseEnvelope *protobundle.Bundle_DsseEnvelope) (string, error) {
	if dsseEnvelope == nil || dsseEnvelope.DsseEnvelope == nil {
		return "", errors.New("DSSE envelope is nil")
	}

	env := dsseEnvelope.DsseEnvelope

	// Decode the outer DSSE payload
	outerPayloadBytes, err := base64.StdEncoding.DecodeString(string(env.Payload))
	if err != nil {
		outerPayloadBytes = env.Payload
	}

	// Try parsing outer DSSE (which might contain inner payload)
	var outer struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}
	if err := json.Unmarshal(outerPayloadBytes, &outer); err == nil && outer.PayloadType != "" {
		innerPayloadBytes, err := base64.StdEncoding.DecodeString(outer.Payload)
		if err == nil {
			// Replace payloadBytes with inner payload for further parsing
			outerPayloadBytes = innerPayloadBytes
		}
	}

	// Try to parse the actual in-toto statement
	var statement struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}

	if err := json.Unmarshal(outerPayloadBytes, &statement); err == nil && len(statement.Subject) > 0 {
		if digest, ok := statement.Subject[0].Digest["sha256"]; ok {
			return digest, nil
		}
		for _, digest := range statement.Subject[0].Digest {
			return digest, nil
		}
	}

	// Fallback: try parsing as Cosign DSSE metadata
	var cosignDSSE struct {
		Spec struct {
			PayloadHash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"payloadHash"`
		} `json:"spec"`
	}

	if err := json.Unmarshal(outerPayloadBytes, &cosignDSSE); err == nil {
		if cosignDSSE.Spec.PayloadHash.Value != "" {
			return cosignDSSE.Spec.PayloadHash.Value, nil
		}
	}

	return "", fmt.Errorf("no subject found in DSSE payload (decoded inner payload: %s)", string(outerPayloadBytes))
}

// getSANFromCert extracts the SAN from a certificate
func getSANFromCert(cert string) (san string, err error) {
	data := []byte(cert)
	block, _ := pem.Decode(data)
	if block == nil {
		return "", errors.New("failed to decode PEM block containing certificate")
	}
	if block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("PEM block is not of type CERTIFICATE, but %s", block.Type)
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Prioritize URI SANs
	if len(certificate.URIs) > 0 {
		return certificate.URIs[0].String(), nil
	}

	// Fall back to email SANs
	if len(certificate.EmailAddresses) > 0 {
		return certificate.EmailAddresses[0], nil
	}

	return "", errors.New("certificate does not contain a supported SAN (URI or Email)")
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

// CertWithPEM holds a parsed certificate and the original PEM block.
type CertWithPEM struct {
	Cert *x509.Certificate
	PEM  string
}

// parsePEMCertificates parses one or more PEM certificates from a string and returns a slice of parsed certificates along with their PEMs.
func parsePEMCertificates(pemData string) ([]CertWithPEM, error) {
	var result []CertWithPEM
	data := []byte(pemData)
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		certPEM := pem.EncodeToMemory(block)
		if certPEM == nil {
			data = rest
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		result = append(result, CertWithPEM{
			Cert: cert,
			PEM:  string(certPEM),
		})
		data = rest
	}
	return result, nil
}

// identifyCertRole classifies a certificate as leaf, intermediate, root, or unknown.
func identifyCertRole(cert *x509.Certificate) models.CertificateRole {
	if cert == nil {
		return models.CertificateRoleUnknown
	}

	// Leaf certificate: not a CA
	if !cert.IsCA {
		return models.CertificateRoleLeaf
	}

	// Check for self-signed: subject == issuer
	isSelfSigned := bytes.Equal(cert.RawSubject, cert.RawIssuer)

	// Verify signature with its own public key
	if isSelfSigned {
		if err := cert.CheckSignatureFrom(cert); err != nil {
			isSelfSigned = false
		}
	}

	if isSelfSigned {
		return models.CertificateRoleRoot
	}

	// CA but not self-signed
	return models.CertificateRoleIntermediate
}

// mergeSANs returns a combined list of all SAN entries from the certificate.
func mergeSANs(cert *x509.Certificate) []string {
	var out []string
	// DNS Names
	out = append(out, cert.DNSNames...)
	// Email Addresses
	out = append(out, cert.EmailAddresses...)
	// IP Addresses
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	// URIs
	for _, uri := range cert.URIs {
		out = append(out, uri.String())
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

var oidRegex = regexp.MustCompile(`^\d+(\.\d+)+$`)

// classifyIdentity infers the identity type (ip, email, uri, oid, subject, dns, other) from its string value.
func classifyIdentity(s string) string {
	// IP address
	if net.ParseIP(s) != nil {
		return "ip"
	}

	// Email
	if strings.Contains(s, "@") {
		return "email"
	}

	// URI
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return "uri"
	}

	// OID (1.2.3.4.5)
	if oidRegex.MatchString(s) {
		return "oid"
	}

	// Subject-DN or Issuer-DN (CN=…, O=…, etc)
	if strings.Contains(s, "=") {
		return "subject"
	}

	// DNS heuristic
	if strings.Contains(s, ".") {
		return "dns"
	}

	return "other"
}

// dedupeIdentities removes duplicate identities (by source/type/value) and assigns sequential IDs.
func dedupeIdentities(all []models.ArtifactIdentity) []models.ArtifactIdentity {
	seen := make(map[string]bool)
	deduped := make([]models.ArtifactIdentity, 0, len(all))

	for _, id := range all {
		// uniqueness key = source|type|value
		key := fmt.Sprintf("%s|%s|%s", id.Source, id.Type, id.Value)

		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, id)
		}
	}

	for i := range deduped {
		deduped[i].Id = i
	}

	return deduped
}

// ComputeTimeCoherenceSummary returns the time coherence summary
func ComputeTimeCoherenceSummary(verifyArtifactResponse models.VerifyArtifactResponse) models.TimeCoherenceSummary {

	var times []time.Time
	signatures := verifyArtifactResponse.Signatures
	attestations := verifyArtifactResponse.Attestations

	for _, s := range signatures {
		if s.Timestamp != nil {
			times = append(times, *s.Timestamp)
		}
	}

	for _, a := range attestations {
		if a.Timestamp != nil {
			times = append(times, *a.Timestamp)
		}
	}

	// Determine status
	// No timestamps at all
	if len(times) == 0 {
		return models.TimeCoherenceSummary{
			Status: models.TimeCoherenceSummaryStatusUnknown,
		}
	}

	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })

	minTime := times[0]
	maxTime := times[len(times)-1]

	status := models.TimeCoherenceSummaryStatusOk
	diff := maxTime.Sub(minTime)
	const maxAllowedSkew = 24 * time.Hour // 1 Day

	if diff > maxAllowedSkew {
		status = models.TimeCoherenceSummaryStatusWarning
	}

	// If any future timestamp: Error
	if maxTime.After(time.Now().UTC().Add(2 * time.Minute)) {
		status = models.TimeCoherenceSummaryStatusError
	}

	return models.TimeCoherenceSummary{
		Status:            status,
		MinIntegratedTime: &minTime,
		MaxIntegratedTime: &maxTime,
	}
}
