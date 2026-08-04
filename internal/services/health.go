package services

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/securesign/rhtas-console/internal/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var securesignGVR = schema.GroupVersionResource{
	Group:    "rhtas.redhat.com",
	Version:  "v1alpha1",
	Resource: "securesigns",
}

type HealthService interface {
	GetSystemHealth(ctx context.Context) (models.SystemHealthResponse, int, error)
}

type healthService struct {
	dynamicClient dynamic.Interface
	namespace     string
}

func NewHealthService() (HealthService, error) {
	config, err := getKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes config: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		namespace = "trusted-artifact-signer"
	}

	return &healthService{
		dynamicClient: dynamicClient,
		namespace:     namespace,
	}, nil
}

func getKubeConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}

	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = os.ExpandEnv("$HOME/.kube/config")
	}

	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

func (h *healthService) GetSystemHealth(ctx context.Context) (models.SystemHealthResponse, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conditions, err := h.getSecuresignConditions(ctx)
	if err != nil {
		return models.SystemHealthResponse{}, http.StatusInternalServerError, fmt.Errorf("failed to read Securesign CR: %w", err)
	}

	return models.SystemHealthResponse{
		SecuresignStatus: mapCondition(conditions["Ready"],
			models.SystemHealthResponseSecuresignStatusHealthy,
			models.SystemHealthResponseSecuresignStatusUnhealthy,
			models.SystemHealthResponseSecuresignStatusUnknown),
		RekorStatus: mapCondition(conditions["RekorAvailable"],
			models.SystemHealthResponseRekorStatusHealthy,
			models.SystemHealthResponseRekorStatusUnhealthy,
			models.SystemHealthResponseRekorStatusUnknown),
		FulcioStatus: mapCondition(conditions["FulcioAvailable"],
			models.SystemHealthResponseFulcioStatusHealthy,
			models.SystemHealthResponseFulcioStatusUnhealthy,
			models.SystemHealthResponseFulcioStatusUnknown),
		CtlogStatus: mapCondition(conditions["CTlogAvailable"],
			models.SystemHealthResponseCtlogStatusHealthy,
			models.SystemHealthResponseCtlogStatusUnhealthy,
			models.SystemHealthResponseCtlogStatusUnknown),
		TrillianStatus: mapCondition(conditions["TrillianAvailable"],
			models.SystemHealthResponseTrillianStatusHealthy,
			models.SystemHealthResponseTrillianStatusUnhealthy,
			models.SystemHealthResponseTrillianStatusUnknown),
		TsaStatus: mapCondition(conditions["TsaAvailable"],
			models.SystemHealthResponseTsaStatusHealthy,
			models.SystemHealthResponseTsaStatusUnhealthy,
			models.SystemHealthResponseTsaStatusUnknown),
		TufStatus: mapCondition(conditions["TufAvailable"],
			models.SystemHealthResponseTufStatusHealthy,
			models.SystemHealthResponseTufStatusUnhealthy,
			models.SystemHealthResponseTufStatusUnknown),
		UpdatedAt: time.Now().UTC(),
	}, http.StatusOK, nil
}

func (h *healthService) getSecuresignConditions(ctx context.Context) (map[string]string, error) {
	crName := os.Getenv("TAS_DEPLOYMENT_NAME")
	if crName == "" {
		crName = "securesign-sample"
	}

	resource, err := h.dynamicClient.Resource(securesignGVR).Namespace(h.namespace).Get(ctx, crName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get securesign CR %q: %w", crName, err)
	}

	rawConditions, found, err := unstructured.NestedSlice(resource.Object, "status", "conditions")
	if err != nil {
		return nil, fmt.Errorf("failed to read conditions: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("no conditions found on securesign CR %q", crName)
	}

	conditions := make(map[string]string, len(rawConditions))
	for _, c := range rawConditions {
		condMap, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		condType, _ := condMap["type"].(string)
		condStatus, _ := condMap["status"].(string)
		if condType != "" {
			conditions[condType] = condStatus
		}
	}

	return conditions, nil
}

func mapCondition[T ~string](status string, healthy, unhealthy, unknown T) T {
	switch status {
	case "True":
		return healthy
	case "False":
		return unhealthy
	default:
		return unknown
	}
}
