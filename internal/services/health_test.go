package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/securesign/rhtas-console/internal/models"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

const testNamespace = "test-ns"

func newTestHealthService(objs []runtime.Object, dynamicObjs ...runtime.Object) *healthService {
	clientset := kubefake.NewSimpleClientset(objs...)
	scheme := runtime.NewScheme()
	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "rhtas.redhat.com", Version: "v1alpha1", Resource: "securesigns"}: "SecuresignList",
		{Group: "rhtas.redhat.com", Version: "v1alpha1", Resource: "rekors"}:      "RekorList",
		{Group: "rhtas.redhat.com", Version: "v1alpha1", Resource: "tufs"}:        "TufList",
	}
	dynamicClient := fake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind, dynamicObjs...)
	return &healthService{
		clientset:     clientset,
		dynamicClient: dynamicClient,
		namespace:     testNamespace,
	}
}

var resourceToKind = map[string]string{
	"securesigns": "Securesign",
	"rekors":      "Rekor",
	"tufs":        "Tuf",
}

func makeUnstructuredCR(resource, name, namespace string, conditions []interface{}) *unstructured.Unstructured {
	kind := resourceToKind[resource]
	if kind == "" {
		kind = resource
	}
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "rhtas.redhat.com",
		Version: "v1alpha1",
		Kind:    kind,
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

func TestCheckDeploymentHealth(t *testing.T) {
	tests := []struct {
		name       string
		deployment *appsv1.Deployment
		want       bool
	}{
		{
			name: "healthy: ready equals replicas",
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test-deploy", Namespace: testNamespace},
				Status: appsv1.DeploymentStatus{
					Replicas:      3,
					ReadyReplicas: 3,
				},
			},
			want: true,
		},
		{
			name: "unhealthy: ready less than replicas",
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test-deploy", Namespace: testNamespace},
				Status: appsv1.DeploymentStatus{
					Replicas:      3,
					ReadyReplicas: 1,
				},
			},
			want: false,
		},
		{
			name: "unhealthy: zero replicas",
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test-deploy", Namespace: testNamespace},
				Status: appsv1.DeploymentStatus{
					Replicas:      0,
					ReadyReplicas: 0,
				},
			},
			want: false,
		},
		{
			name:       "unhealthy: deployment does not exist",
			deployment: nil,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []runtime.Object
			if tt.deployment != nil {
				objs = append(objs, tt.deployment)
			}
			h := newTestHealthService(objs)
			got := h.checkDeploymentHealth(context.Background(), "test-deploy")
			if got != tt.want {
				t.Errorf("checkDeploymentHealth() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckCustomResourceHealth(t *testing.T) {
	tests := []struct {
		name         string
		cr           *unstructured.Unstructured
		resourceType string
		crName       string
		wantHealthy  bool
		wantErr      bool
	}{
		{
			name: "ready condition true",
			cr: makeUnstructuredCR("securesigns", "my-cr", testNamespace, []interface{}{
				map[string]interface{}{
					"type":   "Ready",
					"status": "True",
				},
			}),
			resourceType: "securesigns",
			crName:       "my-cr",
			wantHealthy:  true,
			wantErr:      false,
		},
		{
			name: "ready condition false",
			cr: makeUnstructuredCR("securesigns", "my-cr", testNamespace, []interface{}{
				map[string]interface{}{
					"type":   "Ready",
					"status": "False",
				},
			}),
			resourceType: "securesigns",
			crName:       "my-cr",
			wantHealthy:  false,
			wantErr:      false,
		},
		{
			name:         "CR does not exist",
			cr:           nil,
			resourceType: "securesigns",
			crName:       "missing-cr",
			wantHealthy:  false,
			wantErr:      true,
		},
		{
			name:         "CR with no conditions",
			cr:           makeUnstructuredCR("securesigns", "my-cr", testNamespace, nil),
			resourceType: "securesigns",
			crName:       "my-cr",
			wantHealthy:  false,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dynamicObjs []runtime.Object
			if tt.cr != nil {
				dynamicObjs = append(dynamicObjs, tt.cr)
			}
			h := newTestHealthService(nil, dynamicObjs...)
			got, err := h.checkCustomResourceHealth(context.Background(), tt.resourceType, tt.crName)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tt.wantHealthy {
				t.Errorf("checkCustomResourceHealth() = %v, want %v", got, tt.wantHealthy)
			}
		})
	}
}

func TestCheckHTTPHealth(t *testing.T) {
	t.Run("server returns 200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		h := newTestHealthService(nil)
		if !h.checkHTTPHealth(context.Background(), srv.URL) {
			t.Error("expected true for 200 response")
		}
	})

	t.Run("server returns 500", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		h := newTestHealthService(nil)
		if h.checkHTTPHealth(context.Background(), srv.URL) {
			t.Error("expected false for 500 response")
		}
	})

	t.Run("server unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.Close()

		h := newTestHealthService(nil)
		if h.checkHTTPHealth(context.Background(), srv.URL) {
			t.Error("expected false for unreachable server")
		}
	})
}

func TestCheckSigstoreServicesHealth(t *testing.T) {
	t.Run("healthy CR", func(t *testing.T) {
		t.Setenv("TAS_DEPLOYMENT_NAME", "securesign-sample")
		cr := makeUnstructuredCR("securesigns", "securesign-sample", testNamespace, []interface{}{
			map[string]interface{}{"type": "Ready", "status": "True"},
		})
		h := newTestHealthService(nil, cr)
		got := h.checkSigstoreServicesHealth(context.Background())
		if got != models.SystemHealthResponseSigstoreServicesHealthy {
			t.Errorf("got %q, want %q", got, models.SystemHealthResponseSigstoreServicesHealthy)
		}
	})

	t.Run("unhealthy CR", func(t *testing.T) {
		t.Setenv("TAS_DEPLOYMENT_NAME", "securesign-sample")
		cr := makeUnstructuredCR("securesigns", "securesign-sample", testNamespace, []interface{}{
			map[string]interface{}{"type": "Ready", "status": "False"},
		})
		h := newTestHealthService(nil, cr)
		got := h.checkSigstoreServicesHealth(context.Background())
		if got != models.SystemHealthResponseSigstoreServicesUnhealthy {
			t.Errorf("got %q, want %q", got, models.SystemHealthResponseSigstoreServicesUnhealthy)
		}
	})
}

func TestCheckTUFHealth(t *testing.T) {
	t.Run("TUF_CR_NAME not set", func(t *testing.T) {
		t.Setenv("TUF_CR_NAME", "")
		h := newTestHealthService(nil)
		got := h.checkTUFHealth(context.Background())
		if got != models.SystemHealthResponseTufStatusUnknown {
			t.Errorf("got %q, want %q", got, models.SystemHealthResponseTufStatusUnknown)
		}
	})

	t.Run("healthy CR and deployment", func(t *testing.T) {
		t.Setenv("TUF_CR_NAME", "my-tuf")
		t.Setenv("TUF_DEPLOYMENT_NAME", "tuf")

		cr := makeUnstructuredCR("tufs", "my-tuf", testNamespace, []interface{}{
			map[string]interface{}{"type": "Ready", "status": "True"},
		})
		deploy := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "tuf", Namespace: testNamespace},
			Status:     appsv1.DeploymentStatus{Replicas: 1, ReadyReplicas: 1},
		}
		h := newTestHealthService([]runtime.Object{deploy}, cr)
		got := h.checkTUFHealth(context.Background())
		if got != models.SystemHealthResponseTufStatusHealthy {
			t.Errorf("got %q, want %q", got, models.SystemHealthResponseTufStatusHealthy)
		}
	})

	t.Run("unhealthy CR", func(t *testing.T) {
		t.Setenv("TUF_CR_NAME", "my-tuf")
		t.Setenv("TUF_DEPLOYMENT_NAME", "tuf")

		cr := makeUnstructuredCR("tufs", "my-tuf", testNamespace, []interface{}{
			map[string]interface{}{"type": "Ready", "status": "False"},
		})
		h := newTestHealthService(nil, cr)
		got := h.checkTUFHealth(context.Background())
		if got != models.SystemHealthResponseTufStatusUnhealthy {
			t.Errorf("got %q, want %q", got, models.SystemHealthResponseTufStatusUnhealthy)
		}
	})

	t.Run("unhealthy deployment", func(t *testing.T) {
		t.Setenv("TUF_CR_NAME", "my-tuf")
		t.Setenv("TUF_DEPLOYMENT_NAME", "tuf")

		cr := makeUnstructuredCR("tufs", "my-tuf", testNamespace, []interface{}{
			map[string]interface{}{"type": "Ready", "status": "True"},
		})
		deploy := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "tuf", Namespace: testNamespace},
			Status:     appsv1.DeploymentStatus{Replicas: 2, ReadyReplicas: 0},
		}
		h := newTestHealthService([]runtime.Object{deploy}, cr)
		got := h.checkTUFHealth(context.Background())
		if got != models.SystemHealthResponseTufStatusUnhealthy {
			t.Errorf("got %q, want %q", got, models.SystemHealthResponseTufStatusUnhealthy)
		}
	})
}

func TestCheckRekorHealth(t *testing.T) {
	t.Run("REKOR_CR_NAME not set", func(t *testing.T) {
		t.Setenv("REKOR_CR_NAME", "")
		h := newTestHealthService(nil)
		got := h.checkRekorHealth(context.Background())
		if got != models.SystemHealthResponseRekorStatusUnknown {
			t.Errorf("got %q, want %q", got, models.SystemHealthResponseRekorStatusUnknown)
		}
	})

	t.Run("unhealthy CR", func(t *testing.T) {
		t.Setenv("REKOR_CR_NAME", "my-rekor")
		t.Setenv("REKOR_DEPLOYMENT_NAME", "rekor-server")

		cr := makeUnstructuredCR("rekors", "my-rekor", testNamespace, []interface{}{
			map[string]interface{}{"type": "Ready", "status": "False"},
		})
		h := newTestHealthService(nil, cr)
		got := h.checkRekorHealth(context.Background())
		if got != models.SystemHealthResponseRekorStatusUnhealthy {
			t.Errorf("got %q, want %q", got, models.SystemHealthResponseRekorStatusUnhealthy)
		}
	})

	t.Run("healthy CR but unhealthy deployment", func(t *testing.T) {
		t.Setenv("REKOR_CR_NAME", "my-rekor")
		t.Setenv("REKOR_DEPLOYMENT_NAME", "rekor-server")

		cr := makeUnstructuredCR("rekors", "my-rekor", testNamespace, []interface{}{
			map[string]interface{}{"type": "Ready", "status": "True"},
		})
		deploy := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "rekor-server", Namespace: testNamespace},
			Status:     appsv1.DeploymentStatus{Replicas: 2, ReadyReplicas: 0},
		}
		h := newTestHealthService([]runtime.Object{deploy}, cr)
		got := h.checkRekorHealth(context.Background())
		if got != models.SystemHealthResponseRekorStatusUnhealthy {
			t.Errorf("got %q, want %q", got, models.SystemHealthResponseRekorStatusUnhealthy)
		}
	})
}

func TestGetSystemHealth(t *testing.T) {
	t.Run("missing env vars returns unknown for rekor and tuf", func(t *testing.T) {
		t.Setenv("REKOR_CR_NAME", "")
		t.Setenv("TUF_CR_NAME", "")
		t.Setenv("TAS_DEPLOYMENT_NAME", "securesign-sample")

		cr := makeUnstructuredCR("securesigns", "securesign-sample", testNamespace, []interface{}{
			map[string]interface{}{"type": "Ready", "status": "True"},
		})
		h := newTestHealthService(nil, cr)
		resp, statusCode, err := h.GetSystemHealth(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if statusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", statusCode, http.StatusOK)
		}
		if resp.RekorStatus != models.SystemHealthResponseRekorStatusUnknown {
			t.Errorf("RekorStatus = %q, want %q", resp.RekorStatus, models.SystemHealthResponseRekorStatusUnknown)
		}
		if resp.TufStatus != models.SystemHealthResponseTufStatusUnknown {
			t.Errorf("TufStatus = %q, want %q", resp.TufStatus, models.SystemHealthResponseTufStatusUnknown)
		}
		if resp.SigstoreServices != models.SystemHealthResponseSigstoreServicesHealthy {
			t.Errorf("SigstoreServices = %q, want %q", resp.SigstoreServices, models.SystemHealthResponseSigstoreServicesHealthy)
		}
	})
}
