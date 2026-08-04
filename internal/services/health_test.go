package services

import (
	"context"
	"net/http"
	"testing"

	"github.com/securesign/rhtas-console/internal/models"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

const testNamespace = "test-ns"

func newTestHealthService(dynamicObjs ...runtime.Object) *healthService {
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		securesignGVR: "SecuresignList",
	}
	dynamicClient := fake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind, dynamicObjs...)
	return &healthService{
		dynamicClient: dynamicClient,
		namespace:     testNamespace,
	}
}

func makeSecuresignCR(name, namespace string, conditions []interface{}) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "rhtas.redhat.com",
		Version: "v1alpha1",
		Kind:    "Securesign",
	})
	obj.SetName(name)
	obj.SetNamespace(namespace)
	if conditions != nil {
		obj.Object["status"] = map[string]interface{}{
			"conditions": conditions,
		}
	}
	return obj
}

func cond(condType, status string) map[string]interface{} {
	return map[string]interface{}{"type": condType, "status": status}
}

func allHealthyConditions() []interface{} {
	return []interface{}{
		cond("Ready", "True"),
		cond("RekorAvailable", "True"),
		cond("FulcioAvailable", "True"),
		cond("CTlogAvailable", "True"),
		cond("TrillianAvailable", "True"),
		cond("TsaAvailable", "True"),
		cond("TufAvailable", "True"),
	}
}

func TestGetSecuresignConditions(t *testing.T) {
	t.Run("all conditions present", func(t *testing.T) {
		t.Setenv("TAS_DEPLOYMENT_NAME", "securesign-sample")
		cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions())
		h := newTestHealthService(cr)

		conditions, err := h.getSecuresignConditions(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(conditions) != 7 {
			t.Errorf("expected 7 conditions, got %d", len(conditions))
		}
		if conditions["Ready"] != "True" {
			t.Errorf("Ready = %q, want %q", conditions["Ready"], "True")
		}
	})

	t.Run("CR not found", func(t *testing.T) {
		t.Setenv("TAS_DEPLOYMENT_NAME", "missing")
		h := newTestHealthService()

		_, err := h.getSecuresignConditions(context.Background())
		if err == nil {
			t.Error("expected error for missing CR, got nil")
		}
	})

	t.Run("CR with no conditions", func(t *testing.T) {
		t.Setenv("TAS_DEPLOYMENT_NAME", "securesign-sample")
		cr := makeSecuresignCR("securesign-sample", testNamespace, nil)
		h := newTestHealthService(cr)

		_, err := h.getSecuresignConditions(context.Background())
		if err == nil {
			t.Error("expected error for missing conditions, got nil")
		}
	})
}

func TestMapCondition(t *testing.T) {
	type result = models.SystemHealthResponseRekorStatus
	healthy := models.SystemHealthResponseRekorStatusHealthy
	unhealthy := models.SystemHealthResponseRekorStatusUnhealthy
	unknown := models.SystemHealthResponseRekorStatusUnknown

	tests := []struct {
		status string
		want   result
	}{
		{"True", healthy},
		{"False", unhealthy},
		{"", unknown},
		{"Unknown", unknown},
	}

	for _, tt := range tests {
		got := mapCondition(tt.status, healthy, unhealthy, unknown)
		if got != tt.want {
			t.Errorf("mapCondition(%q) = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestGetSystemHealth(t *testing.T) {
	t.Run("all components healthy", func(t *testing.T) {
		t.Setenv("TAS_DEPLOYMENT_NAME", "securesign-sample")
		cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions())
		h := newTestHealthService(cr)

		resp, statusCode, err := h.GetSystemHealth(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if statusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", statusCode, http.StatusOK)
		}
		if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusHealthy {
			t.Errorf("SecuresignStatus = %q, want %q", resp.SecuresignStatus, models.SystemHealthResponseSecuresignStatusHealthy)
		}
		if resp.RekorStatus != models.SystemHealthResponseRekorStatusHealthy {
			t.Errorf("RekorStatus = %q, want %q", resp.RekorStatus, models.SystemHealthResponseRekorStatusHealthy)
		}
		if resp.FulcioStatus != models.SystemHealthResponseFulcioStatusHealthy {
			t.Errorf("FulcioStatus = %q, want %q", resp.FulcioStatus, models.SystemHealthResponseFulcioStatusHealthy)
		}
		if resp.CtlogStatus != models.SystemHealthResponseCtlogStatusHealthy {
			t.Errorf("CtlogStatus = %q, want %q", resp.CtlogStatus, models.SystemHealthResponseCtlogStatusHealthy)
		}
		if resp.TrillianStatus != models.SystemHealthResponseTrillianStatusHealthy {
			t.Errorf("TrillianStatus = %q, want %q", resp.TrillianStatus, models.SystemHealthResponseTrillianStatusHealthy)
		}
		if resp.TsaStatus != models.SystemHealthResponseTsaStatusHealthy {
			t.Errorf("TsaStatus = %q, want %q", resp.TsaStatus, models.SystemHealthResponseTsaStatusHealthy)
		}
		if resp.TufStatus != models.SystemHealthResponseTufStatusHealthy {
			t.Errorf("TufStatus = %q, want %q", resp.TufStatus, models.SystemHealthResponseTufStatusHealthy)
		}
	})

	t.Run("mixed component statuses", func(t *testing.T) {
		t.Setenv("TAS_DEPLOYMENT_NAME", "securesign-sample")
		cr := makeSecuresignCR("securesign-sample", testNamespace, []interface{}{
			cond("Ready", "False"),
			cond("RekorAvailable", "True"),
			cond("FulcioAvailable", "False"),
			cond("CTlogAvailable", "True"),
			cond("TrillianAvailable", "False"),
			cond("TsaAvailable", "True"),
			cond("TufAvailable", "False"),
		})
		h := newTestHealthService(cr)

		resp, statusCode, err := h.GetSystemHealth(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if statusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", statusCode, http.StatusOK)
		}
		if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusUnhealthy {
			t.Errorf("SecuresignStatus = %q, want %q", resp.SecuresignStatus, models.SystemHealthResponseSecuresignStatusUnhealthy)
		}
		if resp.RekorStatus != models.SystemHealthResponseRekorStatusHealthy {
			t.Errorf("RekorStatus = %q, want %q", resp.RekorStatus, models.SystemHealthResponseRekorStatusHealthy)
		}
		if resp.FulcioStatus != models.SystemHealthResponseFulcioStatusUnhealthy {
			t.Errorf("FulcioStatus = %q, want %q", resp.FulcioStatus, models.SystemHealthResponseFulcioStatusUnhealthy)
		}
		if resp.CtlogStatus != models.SystemHealthResponseCtlogStatusHealthy {
			t.Errorf("CtlogStatus = %q, want %q", resp.CtlogStatus, models.SystemHealthResponseCtlogStatusHealthy)
		}
		if resp.TrillianStatus != models.SystemHealthResponseTrillianStatusUnhealthy {
			t.Errorf("TrillianStatus = %q, want %q", resp.TrillianStatus, models.SystemHealthResponseTrillianStatusUnhealthy)
		}
		if resp.TsaStatus != models.SystemHealthResponseTsaStatusHealthy {
			t.Errorf("TsaStatus = %q, want %q", resp.TsaStatus, models.SystemHealthResponseTsaStatusHealthy)
		}
		if resp.TufStatus != models.SystemHealthResponseTufStatusUnhealthy {
			t.Errorf("TufStatus = %q, want %q", resp.TufStatus, models.SystemHealthResponseTufStatusUnhealthy)
		}
	})

	t.Run("CR not found returns error", func(t *testing.T) {
		t.Setenv("TAS_DEPLOYMENT_NAME", "missing")
		h := newTestHealthService()

		_, statusCode, err := h.GetSystemHealth(context.Background())
		if err == nil {
			t.Fatal("expected error for missing CR, got nil")
		}
		if statusCode != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", statusCode, http.StatusInternalServerError)
		}
	})

	t.Run("missing condition returns unknown for that component", func(t *testing.T) {
		t.Setenv("TAS_DEPLOYMENT_NAME", "securesign-sample")
		cr := makeSecuresignCR("securesign-sample", testNamespace, []interface{}{
			cond("Ready", "True"),
			cond("RekorAvailable", "True"),
		})
		h := newTestHealthService(cr)

		resp, _, err := h.GetSystemHealth(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusHealthy {
			t.Errorf("SecuresignStatus = %q, want %q", resp.SecuresignStatus, models.SystemHealthResponseSecuresignStatusHealthy)
		}
		if resp.RekorStatus != models.SystemHealthResponseRekorStatusHealthy {
			t.Errorf("RekorStatus = %q, want %q", resp.RekorStatus, models.SystemHealthResponseRekorStatusHealthy)
		}
		if resp.FulcioStatus != models.SystemHealthResponseFulcioStatusUnknown {
			t.Errorf("FulcioStatus = %q, want %q", resp.FulcioStatus, models.SystemHealthResponseFulcioStatusUnknown)
		}
		if resp.TsaStatus != models.SystemHealthResponseTsaStatusUnknown {
			t.Errorf("TsaStatus = %q, want %q", resp.TsaStatus, models.SystemHealthResponseTsaStatusUnknown)
		}
	})

	t.Run("defaults to securesign-sample when TAS_DEPLOYMENT_NAME not set", func(t *testing.T) {
		t.Setenv("TAS_DEPLOYMENT_NAME", "")
		cr := makeSecuresignCR("securesign-sample", testNamespace, allHealthyConditions())
		h := newTestHealthService(cr)

		resp, statusCode, err := h.GetSystemHealth(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if statusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", statusCode, http.StatusOK)
		}
		if resp.SecuresignStatus != models.SystemHealthResponseSecuresignStatusHealthy {
			t.Errorf("SecuresignStatus = %q, want %q", resp.SecuresignStatus, models.SystemHealthResponseSecuresignStatusHealthy)
		}
	})
}
