package services

import (
	"testing"

	"github.com/securesign/rhtas-console/internal/models"
)

func TestDeriveOverallStatus(t *testing.T) {
	tests := []struct {
		name           string
		tasStatus      models.SystemHealthResponseTasStatus
		rekorStatus    models.SystemHealthResponseRekorStatus
		tufStatus      models.SystemHealthResponseTufStatus
		expectedStatus models.SystemHealthResponseOverallStatus
	}{
		{
			name:           "All components healthy",
			tasStatus:      models.SystemHealthResponseTasStatusHealthy,
			rekorStatus:    models.SystemHealthResponseRekorStatusHealthy,
			tufStatus:      models.SystemHealthResponseTufStatusHealthy,
			expectedStatus: models.SystemHealthResponseOverallStatusHealthy,
		},
		{
			name:           "TAS unhealthy, others healthy - degraded",
			tasStatus:      models.SystemHealthResponseTasStatusUnhealthy,
			rekorStatus:    models.SystemHealthResponseRekorStatusHealthy,
			tufStatus:      models.SystemHealthResponseTufStatusHealthy,
			expectedStatus: models.SystemHealthResponseOverallStatusDegraded,
		},
		{
			name:           "Rekor unhealthy, others healthy - degraded",
			tasStatus:      models.SystemHealthResponseTasStatusHealthy,
			rekorStatus:    models.SystemHealthResponseRekorStatusUnhealthy,
			tufStatus:      models.SystemHealthResponseTufStatusHealthy,
			expectedStatus: models.SystemHealthResponseOverallStatusDegraded,
		},
		{
			name:           "TUF unhealthy, others healthy - degraded",
			tasStatus:      models.SystemHealthResponseTasStatusHealthy,
			rekorStatus:    models.SystemHealthResponseRekorStatusHealthy,
			tufStatus:      models.SystemHealthResponseTufStatusUnhealthy,
			expectedStatus: models.SystemHealthResponseOverallStatusDegraded,
		},
		{
			name:           "All components unhealthy",
			tasStatus:      models.SystemHealthResponseTasStatusUnhealthy,
			rekorStatus:    models.SystemHealthResponseRekorStatusUnhealthy,
			tufStatus:      models.SystemHealthResponseTufStatusUnhealthy,
			expectedStatus: models.SystemHealthResponseOverallStatusUnhealthy,
		},
		{
			name:           "Only TAS healthy - degraded",
			tasStatus:      models.SystemHealthResponseTasStatusHealthy,
			rekorStatus:    models.SystemHealthResponseRekorStatusUnhealthy,
			tufStatus:      models.SystemHealthResponseTufStatusUnhealthy,
			expectedStatus: models.SystemHealthResponseOverallStatusDegraded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &healthService{}
			result := h.deriveOverallStatus(tt.tasStatus, tt.rekorStatus, tt.tufStatus)
			if result != tt.expectedStatus {
				t.Errorf("deriveOverallStatus() = %v, want %v", result, tt.expectedStatus)
			}
		})
	}
}

func TestGetNestedField(t *testing.T) {
	tests := []struct {
		name          string
		obj           map[string]interface{}
		fields        []string
		expectedValue interface{}
		expectedFound bool
		expectedError bool
	}{
		{
			name: "Single level field exists",
			obj: map[string]interface{}{
				"status": "healthy",
			},
			fields:        []string{"status"},
			expectedValue: "healthy",
			expectedFound: true,
			expectedError: false,
		},
		{
			name: "Nested field exists",
			obj: map[string]interface{}{
				"status": map[string]interface{}{
					"conditions": []interface{}{
						map[string]interface{}{
							"type":   "Ready",
							"status": "True",
						},
					},
				},
			},
			fields: []string{"status", "conditions"},
			expectedValue: []interface{}{
				map[string]interface{}{
					"type":   "Ready",
					"status": "True",
				},
			},
			expectedFound: true,
			expectedError: false,
		},
		{
			name: "Field does not exist",
			obj: map[string]interface{}{
				"status": "healthy",
			},
			fields:        []string{"nonexistent"},
			expectedValue: nil,
			expectedFound: false,
			expectedError: false,
		},
		{
			name: "Nested field parent not a map",
			obj: map[string]interface{}{
				"status": "healthy",
			},
			fields:        []string{"status", "conditions"},
			expectedValue: nil,
			expectedFound: false,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, found, err := getNestedField(tt.obj, tt.fields...)

			if (err != nil) != tt.expectedError {
				t.Errorf("getNestedField() error = %v, expectedError %v", err, tt.expectedError)
				return
			}

			if found != tt.expectedFound {
				t.Errorf("getNestedField() found = %v, want %v", found, tt.expectedFound)
			}

			if tt.expectedFound && value == nil && tt.expectedValue != nil {
				t.Errorf("getNestedField() value = %v, want %v", value, tt.expectedValue)
			}
		})
	}
}
