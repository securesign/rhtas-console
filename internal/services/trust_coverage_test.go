package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestGetTrustCoverage_NoRekorURL(t *testing.T) {
	// Clear environment
	os.Unsetenv("REKOR_URL")
	os.Unsetenv("MOCK_MODE")

	s := &trustService{}
	_, statusCode, err := s.GetTrustCoverage(context.Background(), "", nil, "")

	if statusCode != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, statusCode)
	}
	if err == nil {
		t.Error("Expected error when REKOR_URL not set")
	}
}

func TestGetTrustCoverage_MockMode(t *testing.T) {
	os.Unsetenv("REKOR_URL")
	os.Setenv("MOCK_MODE", "true")
	defer os.Unsetenv("MOCK_MODE")

	s := &trustService{}
	result, statusCode, err := s.GetTrustCoverage(context.Background(), "", nil, "")

	if err != nil {
		t.Errorf("Unexpected error in mock mode: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, statusCode)
	}
	if result.TotalArtifacts == 0 {
		t.Error("Mock data should have non-zero artifacts")
	}
}

func TestGetTrustCoverage_EmptyRekorLog(t *testing.T) {
	// Create mock Rekor server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/log" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"treeSize": 0,
			})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	os.Setenv("REKOR_URL", server.URL)
	defer os.Unsetenv("REKOR_URL")

	s := &trustService{}
	result, statusCode, err := s.GetTrustCoverage(context.Background(), "", nil, "")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, statusCode)
	}
	if result.TotalArtifacts != 0 {
		t.Errorf("Expected 0 artifacts, got %d", result.TotalArtifacts)
	}
	if result.AttestedCount != 0 {
		t.Errorf("Expected 0 attested, got %d", result.AttestedCount)
	}
	if result.UnattestedCount != 0 {
		t.Errorf("Expected 0 unattested, got %d", result.UnattestedCount)
	}
}

func TestGetTrustCoverage_AllAttested(t *testing.T) {
	// Create mock Rekor entry with dsse type
	dsseEntry := rekorEntryBody{
		APIVersion: "0.0.1",
		Kind:       "dsse",
	}
	dsseBodyJSON, _ := json.Marshal(dsseEntry)
	dsseBodyB64 := base64.StdEncoding.EncodeToString(dsseBodyJSON)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/log" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"treeSize": 3,
			})
			return
		}
		if r.URL.Path == "/api/v1/log/entries" {
			// Return a dsse entry (attested)
			entries := map[string]interface{}{
				"test-uuid": map[string]interface{}{
					"body":           dsseBodyB64,
					"integratedTime": time.Now().Unix(),
					"logID":          "test-log-id",
					"logIndex":       0,
				},
			}
			json.NewEncoder(w).Encode(entries)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	os.Setenv("REKOR_URL", server.URL)
	os.Setenv("REKOR_SCAN_LIMIT", "3")
	defer os.Unsetenv("REKOR_URL")
	defer os.Unsetenv("REKOR_SCAN_LIMIT")

	s := &trustService{}
	result, statusCode, err := s.GetTrustCoverage(context.Background(), "", nil, "")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, statusCode)
	}
	if result.TotalArtifacts != 3 {
		t.Errorf("Expected 3 artifacts, got %d", result.TotalArtifacts)
	}
	if result.AttestedCount != 3 {
		t.Errorf("Expected 3 attested, got %d", result.AttestedCount)
	}
	if result.UnattestedCount != 0 {
		t.Errorf("Expected 0 unattested, got %d", result.UnattestedCount)
	}
	if result.AttestedPercentage != 100.0 {
		t.Errorf("Expected 100%% attested, got %.2f", result.AttestedPercentage)
	}
}

func TestGetTrustCoverage_MixedEntries(t *testing.T) {
	// Create different entry types
	dsseEntry := rekorEntryBody{APIVersion: "0.0.1", Kind: "dsse"}
	hashedrekordEntry := rekorEntryBody{APIVersion: "0.0.1", Kind: "hashedrekord"}

	dsseBodyJSON, _ := json.Marshal(dsseEntry)
	hashedBodyJSON, _ := json.Marshal(hashedrekordEntry)

	dsseBodyB64 := base64.StdEncoding.EncodeToString(dsseBodyJSON)
	hashedBodyB64 := base64.StdEncoding.EncodeToString(hashedBodyJSON)

	entryIndex := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/log" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"treeSize": 5,
			})
			return
		}
		if r.URL.Path == "/api/v1/log/entries" {
			// Alternate between attested and unattested
			body := hashedBodyB64
			if entryIndex%2 == 0 {
				body = dsseBodyB64
			}
			entryIndex++

			entries := map[string]interface{}{
				"test-uuid": map[string]interface{}{
					"body":           body,
					"integratedTime": time.Now().Unix(),
					"logID":          "test-log-id",
					"logIndex":       entryIndex - 1,
				},
			}
			json.NewEncoder(w).Encode(entries)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	os.Setenv("REKOR_URL", server.URL)
	os.Setenv("REKOR_SCAN_LIMIT", "5")
	defer os.Unsetenv("REKOR_URL")
	defer os.Unsetenv("REKOR_SCAN_LIMIT")

	s := &trustService{}
	result, statusCode, err := s.GetTrustCoverage(context.Background(), "", nil, "")

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, statusCode)
	}
	if result.TotalArtifacts != 5 {
		t.Errorf("Expected 5 artifacts, got %d", result.TotalArtifacts)
	}
	if result.AttestedCount != 3 {
		t.Errorf("Expected 3 attested (indexes 0,2,4), got %d", result.AttestedCount)
	}
	if result.UnattestedCount != 2 {
		t.Errorf("Expected 2 unattested, got %d", result.UnattestedCount)
	}
	expectedPercentage := float32(60.0)
	tolerance := float32(0.01)
	if result.AttestedPercentage < expectedPercentage-tolerance || result.AttestedPercentage > expectedPercentage+tolerance {
		t.Errorf("Expected ~%.2f%% attested, got %.2f", expectedPercentage, result.AttestedPercentage)
	}
}

func TestIsEntryAttested(t *testing.T) {
	s := &trustService{}

	tests := []struct {
		name     string
		kind     string
		expected bool
	}{
		{"DSSE is attested", "dsse", true},
		{"Intoto is attested", "intoto", true},
		{"Hashedrekord is not attested", "hashedrekord", false},
		{"Unknown type is not attested", "unknown", false},
		{"Case insensitive DSSE", "DSSE", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := rekorEntryBody{
				APIVersion: "0.0.1",
				Kind:       tt.kind,
			}
			bodyJSON, _ := json.Marshal(body)
			bodyB64 := base64.StdEncoding.EncodeToString(bodyJSON)

			entry := &rekorEntry{
				Body:           bodyB64,
				IntegratedTime: time.Now().Unix(),
				LogID:          "test-log",
				LogIndex:       0,
			}

			result, err := s.isEntryAttested(entry)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Expected %v for kind %s, got %v", tt.expected, tt.kind, result)
			}
		})
	}
}

func TestCalculateCoverageFromRekor_ScanLimit(t *testing.T) {
	dsseEntry := rekorEntryBody{APIVersion: "0.0.1", Kind: "dsse"}
	dsseBodyJSON, _ := json.Marshal(dsseEntry)
	dsseBodyB64 := base64.StdEncoding.EncodeToString(dsseBodyJSON)

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/log/entries" {
			requestCount++
			entries := map[string]interface{}{
				"test-uuid": map[string]interface{}{
					"body":           dsseBodyB64,
					"integratedTime": time.Now().Unix(),
					"logID":          "test-log-id",
					"logIndex":       requestCount - 1,
				},
			}
			json.NewEncoder(w).Encode(entries)
			return
		}
	}))
	defer server.Close()

	os.Setenv("REKOR_SCAN_LIMIT", "10")
	defer os.Unsetenv("REKOR_SCAN_LIMIT")

	s := &trustService{}
	result, err := s.calculateCoverageFromRekor(context.Background(), server.URL, 1000)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should only scan up to the limit (10), not all 1000
	if requestCount != 10 {
		t.Errorf("Expected 10 requests (scan limit), got %d", requestCount)
	}
	if result.TotalArtifacts != 10 {
		t.Errorf("Expected 10 artifacts (scan limit), got %d", result.TotalArtifacts)
	}
}

func TestGetTrustCoverage_RekorUnavailable(t *testing.T) {
	os.Setenv("REKOR_URL", "http://localhost:99999")
	defer os.Unsetenv("REKOR_URL")

	s := &trustService{}
	_, statusCode, err := s.GetTrustCoverage(context.Background(), "", nil, "")

	if err == nil {
		t.Error("Expected error when Rekor is unavailable")
	}
	if statusCode != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, statusCode)
	}
}

func TestGetMockTrustCoverage(t *testing.T) {
	result := getMockTrustCoverage()

	if result.TotalArtifacts <= 0 {
		t.Error("Mock data should have positive total artifacts")
	}
	if result.AttestedCount < 0 {
		t.Error("Mock data should have non-negative attested count")
	}
	if result.UnattestedCount != result.TotalArtifacts-result.AttestedCount {
		t.Errorf("UnattestedCount mismatch: total=%d, attested=%d, unattested=%d",
			result.TotalArtifacts, result.AttestedCount, result.UnattestedCount)
	}
	if result.AttestedPercentage < 0 || result.AttestedPercentage > 100 {
		t.Errorf("Invalid percentage: %.2f", result.AttestedPercentage)
	}
}
