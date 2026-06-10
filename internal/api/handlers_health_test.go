package api

import (
	"testing"

	"github.com/securesign/rhtas-console/internal/models"
)

func TestHealthStatusDerivationRules(t *testing.T) {
	tests := []struct {
		name           string
		tasHealthy     bool
		rekorHealthy   bool
		tufHealthy     bool
		expectedStatus models.SystemHealthResponseOverallStatus
	}{
		{
			name:           "All healthy - overall healthy",
			tasHealthy:     true,
			rekorHealthy:   true,
			tufHealthy:     true,
			expectedStatus: models.SystemHealthResponseOverallStatusHealthy,
		},
		{
			name:           "2 healthy 1 unhealthy - degraded",
			tasHealthy:     true,
			rekorHealthy:   true,
			tufHealthy:     false,
			expectedStatus: models.SystemHealthResponseOverallStatusDegraded,
		},
		{
			name:           "1 healthy 2 unhealthy - degraded",
			tasHealthy:     true,
			rekorHealthy:   false,
			tufHealthy:     false,
			expectedStatus: models.SystemHealthResponseOverallStatusDegraded,
		},
		{
			name:           "All unhealthy - overall unhealthy",
			tasHealthy:     false,
			rekorHealthy:   false,
			tufHealthy:     false,
			expectedStatus: models.SystemHealthResponseOverallStatusUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			healthyCount := 0
			if tt.tasHealthy {
				healthyCount++
			}
			if tt.rekorHealthy {
				healthyCount++
			}
			if tt.tufHealthy {
				healthyCount++
			}

			var actualStatus models.SystemHealthResponseOverallStatus
			if healthyCount == 3 {
				actualStatus = models.SystemHealthResponseOverallStatusHealthy
			} else if healthyCount > 0 {
				actualStatus = models.SystemHealthResponseOverallStatusDegraded
			} else {
				actualStatus = models.SystemHealthResponseOverallStatusUnhealthy
			}

			if actualStatus != tt.expectedStatus {
				t.Errorf("Expected %s, got %s", tt.expectedStatus, actualStatus)
			}
		})
	}
}
