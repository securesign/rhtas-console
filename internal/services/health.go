package services

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/securesign/rhtas-console/internal/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type HealthService interface {
	GetSystemHealth(ctx context.Context) (models.SystemHealthResponse, int, error)
}

type healthService struct {
	clientset *kubernetes.Clientset
	namespace string
}

func NewHealthService() (HealthService, error) {
	config, err := getKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		namespace = "trusted-artifact-signer"
	}

	return &healthService{
		clientset: clientset,
		namespace: namespace,
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
	tasStatus := h.checkTASHealth(ctx)
	rekorStatus := h.checkRekorHealth(ctx)
	tufStatus := h.checkTUFHealth(ctx)

	overallStatus := h.deriveOverallStatus(tasStatus, rekorStatus, tufStatus)

	return models.SystemHealthResponse{
		OverallStatus: overallStatus,
		TasStatus:     tasStatus,
		RekorStatus:   rekorStatus,
		TufStatus:     tufStatus,
		UpdatedAt:     time.Now().UTC(),
	}, http.StatusOK, nil
}

func (h *healthService) checkTASHealth(ctx context.Context) models.SystemHealthResponseTasStatus {
	deploymentName := os.Getenv("TAS_DEPLOYMENT_NAME")
	if deploymentName == "" {
		deploymentName = "securesign-sample"
	}

	crHealthy, err := h.checkCustomResourceHealth(ctx, "securesigns", deploymentName)
	if err != nil || !crHealthy {
		return models.SystemHealthResponseTasStatusUnhealthy
	}

	return models.SystemHealthResponseTasStatusHealthy
}

func (h *healthService) checkRekorHealth(ctx context.Context) models.SystemHealthResponseRekorStatus {
	crName := os.Getenv("REKOR_CR_NAME")
	if crName == "" {
		log.Printf("REKOR_CR_NAME environment variable not set")
		return models.SystemHealthResponseRekorStatusUnknown
	}

	deploymentName := os.Getenv("REKOR_DEPLOYMENT_NAME")
	if deploymentName == "" {
		deploymentName = "rekor-server"
	}

	crHealthy, err := h.checkCustomResourceHealth(ctx, "rekors", crName)
	if err != nil || !crHealthy {
		return models.SystemHealthResponseRekorStatusUnhealthy
	}

	podHealthy := h.checkDeploymentHealth(ctx, deploymentName)
	if !podHealthy {
		return models.SystemHealthResponseRekorStatusUnhealthy
	}

	endpointHealthy := h.checkHTTPHealth(ctx, "http://"+deploymentName+"."+h.namespace+".svc:80/api/v1/log")
	if !endpointHealthy {
		return models.SystemHealthResponseRekorStatusUnhealthy
	}

	return models.SystemHealthResponseRekorStatusHealthy
}

func (h *healthService) checkTUFHealth(ctx context.Context) models.SystemHealthResponseTufStatus {
	crName := os.Getenv("TUF_CR_NAME")
	if crName == "" {
		log.Printf("TUF_CR_NAME environment variable not set")
		return models.SystemHealthResponseTufStatusUnknown
	}

	deploymentName := os.Getenv("TUF_DEPLOYMENT_NAME")
	if deploymentName == "" {
		deploymentName = "tuf"
	}

	crHealthy, err := h.checkCustomResourceHealth(ctx, "tufs", crName)
	if err != nil || !crHealthy {
		return models.SystemHealthResponseTufStatusUnhealthy
	}

	podHealthy := h.checkDeploymentHealth(ctx, deploymentName)
	if !podHealthy {
		return models.SystemHealthResponseTufStatusUnhealthy
	}

	return models.SystemHealthResponseTufStatusHealthy
}

func (h *healthService) checkCustomResourceHealth(ctx context.Context, resourceType, name string) (bool, error) {
	config, err := getKubeConfig()
	if err != nil {
		return false, err
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return false, err
	}

	gvr := schema.GroupVersionResource{
		Group:    "rhtas.redhat.com",
		Version:  "v1alpha1",
		Resource: resourceType,
	}

	resource, err := dynamicClient.Resource(gvr).Namespace(h.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	status, found, err := getNestedField(resource.Object, "status", "conditions")
	if err != nil || !found {
		return false, fmt.Errorf("conditions not found in status")
	}

	conditions, ok := status.([]interface{})
	if !ok {
		return false, fmt.Errorf("conditions is not an array")
	}

	for _, condition := range conditions {
		condMap, ok := condition.(map[string]interface{})
		if !ok {
			continue
		}

		condType, _ := condMap["type"].(string)
		condStatus, _ := condMap["status"].(string)

		if condType == "Ready" && condStatus == "True" {
			return true, nil
		}
	}

	return false, nil
}

func (h *healthService) checkDeploymentHealth(ctx context.Context, deploymentName string) bool {
	deployment, err := h.clientset.AppsV1().Deployments(h.namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return false
	}

	if deployment.Status.Replicas == 0 {
		return false
	}

	if deployment.Status.ReadyReplicas < deployment.Status.Replicas {
		return false
	}

	return true
}

func (h *healthService) checkHTTPHealth(ctx context.Context, url string) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("Failed to close response body: %v", cerr)
		}
	}()

	return resp.StatusCode == http.StatusOK
}

func (h *healthService) deriveOverallStatus(
	tasStatus models.SystemHealthResponseTasStatus,
	rekorStatus models.SystemHealthResponseRekorStatus,
	tufStatus models.SystemHealthResponseTufStatus,
) models.SystemHealthResponseOverallStatus {
	healthyCount := 0
	totalComponents := 3

	if tasStatus == models.SystemHealthResponseTasStatusHealthy {
		healthyCount++
	}
	if rekorStatus == models.SystemHealthResponseRekorStatusHealthy {
		healthyCount++
	}
	if tufStatus == models.SystemHealthResponseTufStatusHealthy {
		healthyCount++
	}

	if healthyCount == totalComponents {
		return models.SystemHealthResponseOverallStatusHealthy
	}

	if healthyCount > 0 {
		return models.SystemHealthResponseOverallStatusDegraded
	}

	return models.SystemHealthResponseOverallStatusUnhealthy
}

func getNestedField(obj map[string]interface{}, fields ...string) (interface{}, bool, error) {
	current := obj
	for i, field := range fields {
		if i == len(fields)-1 {
			val, found := current[field]
			return val, found, nil
		}

		next, found := current[field]
		if !found {
			return nil, false, nil
		}

		nextMap, ok := next.(map[string]interface{})
		if !ok {
			return nil, false, fmt.Errorf("field %s is not a map", field)
		}
		current = nextMap
	}
	return nil, false, nil
}
