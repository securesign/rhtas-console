package verify

import (
	"bytes"
	"context"
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
	"net/http"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/verify"
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
}

func NewVerifyOptions() VerifyOptions {
	return VerifyOptions{
		RequireTimestamp:        true,
		RequireCTLog:            true,
		RequireTLog:             true,
		ArtifactDigestAlgorithm: "sha256",
	}
}

func VerifyArtifact(ctx context.Context, verifyOpts VerifyOptions) (details string, err error) {
	var b *bundle.Bundle

	if verifyOpts.OCIImage != "" {
		// Build a bundle from OCI image reference and get its digest
		b, verifyOpts.ArtifactDigest, err = bundleFromOCIImage(verifyOpts.OCIImage, verifyOpts.RequireTLog, verifyOpts.RequireTimestamp)
	} else if verifyOpts.Bundle != nil {
		// Load the bundle from the provided paramters
		b, err = LoadFromMap(verifyOpts.Bundle)
		if err != nil {
			return "", fmt.Errorf("failed to load bundle from map: %w", err)
		}
	} else {
		return "", fmt.Errorf("either OCIImage or Bundle must be provided")
	}

	if err != nil {
		return "", err
	}

	if verifyOpts.MinBundleVersion != "" {
		if !b.MinVersion(verifyOpts.MinBundleVersion) {
			return "", fmt.Errorf("bundle is not of minimum version %s", verifyOpts.MinBundleVersion)
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
			return "", err
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
		if err := setOptsRoot(opts); err != nil {
			return "", fmt.Errorf("failed to set root in options for %s: %w", verifyOpts.TUFRootURL, err)
		}
		fetcher := fetcher.NewDefaultFetcher()
		fetcher.SetHTTPUserAgent(util.ConstructUserAgent())
		opts.Fetcher = fetcher

		// Load the tuf root.json if provided, if not use public good
		if verifyOpts.TUFTrustedRoot != "" {
			rb, err := os.ReadFile(verifyOpts.TUFTrustedRoot)
			if err != nil {
				return "", fmt.Errorf("failed to read %s: %w",
					verifyOpts.TUFTrustedRoot, err)
			}
			opts.Root = rb
		}

		client, err := tuf.New(opts)
		if err != nil {
			return "", err
		}
		trustedRootJSON, err = client.GetTarget("trusted_root.json")
		if err != nil {
			return "", err
		}
	} else if verifyOpts.TrustedRootJSONPath != "" {
		trustedRootJSON, err = os.ReadFile(verifyOpts.TrustedRootJSONPath)
		if err != nil {
			return "", fmt.Errorf("failed to read %s: %w",
				verifyOpts.TrustedRootJSONPath, err)
		}
	}

	if len(trustedRootJSON) > 0 {
		var trustedRoot *root.TrustedRoot
		trustedRoot, err = root.NewTrustedRootFromJSON(trustedRootJSON)
		if err != nil {
			return "", err
		}
		trustedMaterial = append(trustedMaterial, trustedRoot)
	}
	if verifyOpts.TrustedPublicKey != "" {
		pemBytes, err := os.ReadFile(verifyOpts.TrustedPublicKey)
		if err != nil {
			return "", err
		}
		pemBlock, _ := pem.Decode(pemBytes)
		if pemBlock == nil {
			return "", errors.New("failed to decode pem block")
		}
		pubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return "", err
		}
		trustedMaterial = append(trustedMaterial, trustedPublicKeyMaterial(pubKey))
	}

	if len(trustedMaterial) == 0 {
		return "", errors.New("no trusted material provided")
	}

	sev, err := verify.NewVerifier(trustedMaterial, verifierConfig...)
	if err != nil {
		return "", err
	}

	if verifyOpts.ArtifactDigest != "" { //nolint:gocritic
		artifactDigestBytes, err := hex.DecodeString(verifyOpts.ArtifactDigest)
		if err != nil {
			return "", err
		}
		artifactPolicy = verify.WithArtifactDigest(verifyOpts.ArtifactDigestAlgorithm, artifactDigestBytes)
	} else {
		artifactPolicy = verify.WithoutArtifactUnsafe()
		fmt.Fprintf(os.Stderr, "No artifact provided, skipping artifact verification. This is unsafe!\n")
	}

	res, err := sev.Verify(b, verify.NewPolicy(artifactPolicy, identityPolicies...))
	if err != nil {
		return "", err
	}

	fmt.Fprintf(os.Stderr, "Verification successful!\n")
	marshaled, err := json.MarshalIndent(res, "", "   ")
	if err != nil {
		return "", err
	}
	return string(marshaled), nil
}

func LoadFromMap(m map[string]interface{}) (*bundle.Bundle, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal map to JSON: %w", err)
	}

	var b bundle.Bundle
	b.Bundle = new(protobundle.Bundle)
	if err := b.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON into bundle: %w", err)
	}

	return &b, nil
}

type nonExpiringVerifier struct {
	signature.Verifier
}

func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool {
	return true
}

func trustedPublicKeyMaterial(pk crypto.PublicKey) *root.TrustedPublicKeyMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		verifier, err := signature.LoadECDSAVerifier(pk.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return &nonExpiringVerifier{verifier}, nil
	})
}

// bundleFromOCIImage returns a Bundle based on OCI image reference.
func bundleFromOCIImage(imageRef string, hasTlog, hasTimestamp bool) (*bundle.Bundle, string, error) {
	// 1. Get the simple signing layer
	simpleSigning, err := simpleSigningLayerFromOCIImage(imageRef)
	if err != nil {
		return nil, "", fmt.Errorf("error getting simple signing layer: %w", err)
	}
	// 2. Build the verification material for the bundle
	verificationMaterial, err := getBundleVerificationMaterial(simpleSigning, hasTlog, hasTimestamp)
	if err != nil {
		return nil, "", fmt.Errorf("error getting verification material: %w", err)
	}
	// 3. Build the message signature for the bundle
	msgSignature, err := getBundleMsgSignature(simpleSigning)
	if err != nil {
		return nil, "", fmt.Errorf("error getting message signature: %w", err)
	}
	// 4. Construct and verify the bundle
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
	// 5. Return the bundle and the digest of the simple signing layer (this is what is signed)
	return bun, simpleSigning.Digest.Hex, nil
}

// simpleSigningLayerFromOCIImage returns the simple signing layer from the OCI image reference
func simpleSigningLayerFromOCIImage(imageRef string) (*v1.Descriptor, error) {
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
	// 7. Return the layer - most probably there are more layers (one for each signature) but verifying one is enough
	return &sigManifest.Layers[0], nil
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
	// if hasTimestamp {
	// 	timestampEntries, err = getVerificationMaterialTimestampEntries(manifestLayer)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("error getting timestamp entries: %w", err)
	// 	}
	// }
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
	bun := manifestLayer.Annotations["dev.sigstore.cosign/bundle"]
	var jsonData map[string]interface{}
	err := json.Unmarshal([]byte(bun), &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}

	// 2. Get the log index, log ID, integrated time, signed entry timestamp and body
	logIndex, ok := jsonData["Payload"].(map[string]interface{})["logIndex"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting logIndex")
	}
	li, ok := jsonData["Payload"].(map[string]interface{})["logID"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting logID")
	}
	logID, err := hex.DecodeString(li)
	if err != nil {
		return nil, fmt.Errorf("error decoding logID: %w", err)
	}
	integratedTime, ok := jsonData["Payload"].(map[string]interface{})["integratedTime"].(float64)
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
	body, ok := jsonData["Payload"].(map[string]interface{})["body"].(string)
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
	apiVersion := jsonData["apiVersion"].(string)
	kind := jsonData["kind"].(string)
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
