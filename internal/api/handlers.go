package api

import (
	"encoding/json"
	"net/http"

	_ "embed"

	"errors"

	"github.com/go-chi/chi/v5"
	console_errors "github.com/securesign/rhtas-console/internal/errors"
	"github.com/securesign/rhtas-console/internal/models"
	"github.com/securesign/rhtas-console/internal/services"
)

// Handler implements the ServerInterface
type Handler struct {
	artifactService services.ArtifactService
	rekorService    services.RekorService
	trustService    services.TrustService
}

//go:embed openapi/rhtas-console.yaml
var openAPIYaml []byte

func NewHandler(as services.ArtifactService, rs services.RekorService, ts services.TrustService) *Handler {
	return &Handler{
		artifactService: as,
		rekorService:    rs,
		trustService:    ts,
	}
}

func (h *Handler) GetHealthz(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{"status": "ok"}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) PostApiV1ArtifactsSign(w http.ResponseWriter, r *http.Request) {
	var req models.SignArtifactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resp, err := h.artifactService.SignArtifact(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) PostApiV1ArtifactsVerify(w http.ResponseWriter, r *http.Request) {
	var req models.VerifyArtifactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resp, err := h.artifactService.VerifyArtifact(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) GetApiV1RekorEntriesUuid(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	if uuid == "" {
		writeError(w, http.StatusBadRequest, "missing uuid")
		return
	}
	resp, err := h.rekorService.GetRekorEntry(r.Context(), uuid)
	if err != nil {
		writeError(w, http.StatusNotFound, "missing entry")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) GetApiV1RekorPublicKey(w http.ResponseWriter, r *http.Request) {
	resp, err := h.rekorService.GetRekorPublicKey(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) GetApiV1ArtifactsArtifactPolicies(w http.ResponseWriter, r *http.Request) {
	artifact := chi.URLParam(r, "artifact")
	if artifact == "" {
		writeError(w, http.StatusBadRequest, "missing artifact")
		return
	}
	resp, err := h.artifactService.GetArtifactPolicies(r.Context(), artifact)
	if err != nil {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) GetApiV1TrustConfig(w http.ResponseWriter, r *http.Request) {
	tufRepoUrl := r.URL.Query().Get("tufRepositoryUrl")
	resp, err := h.trustService.GetTrustConfig(r.Context(), tufRepoUrl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) GetApiV1TrustRootMetadata(w http.ResponseWriter, r *http.Request) {
	tufRepoUrl := r.URL.Query().Get("tufRepositoryUrl")
	resp, err := h.trustService.GetTrustRootMetadataInfo(tufRepoUrl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) GetApiV1TrustTargets(w http.ResponseWriter, r *http.Request) {
	tufRepoUrl := r.URL.Query().Get("tufRepositoryUrl")
	resp, err := h.trustService.GetTargetsList(r.Context(), tufRepoUrl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) GetApiV1TrustTarget(w http.ResponseWriter, r *http.Request) {
	tufRepoUrl := r.URL.Query().Get("tufRepositoryUrl")
	target := r.URL.Query().Get("target")
	resp, err := h.trustService.GetTarget(r.Context(), tufRepoUrl, target)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) GetApiV1TrustTargetsCertificates(w http.ResponseWriter, r *http.Request) {
	tufRepoUrl := r.URL.Query().Get("tufRepositoryUrl")
	resp, err := h.trustService.GetCertificatesInfo(r.Context(), tufRepoUrl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) ServeSwaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	const swaggerHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>RHTAS Console Swagger UI</title>
	<link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
	<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
	<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
</head>
<body>
	<div id="swagger-ui"></div>
	<script>
		window.onload = function() {
			SwaggerUIBundle({
				url: "/rhtas-console.yaml",
				dom_id: '#swagger-ui',
				presets: [
					SwaggerUIBundle.presets.apis,
					SwaggerUIStandalonePreset
				],
				layout: "StandaloneLayout"
			});
		};
	</script>
</body>
</html>
`
	if _, err := w.Write([]byte(swaggerHTML)); err != nil {
		http.Error(w, "failed to write response", http.StatusInternalServerError)
		return
	}
}

func (h *Handler) ServeOpenAPIFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/vnd.oai.openapi;version=3.0.0+yaml")
	if _, err := w.Write(openAPIYaml); err != nil {
		http.Error(w, "failed to write response", http.StatusInternalServerError)
		return
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, models.Error{Error: message})
}

func (h *Handler) GetApiV1ArtifactsImage(w http.ResponseWriter, r *http.Request) {

	image := r.URL.Query().Get("uri")
	if image == "" {
		writeError(w, http.StatusBadRequest, "missing image uri")
		return
	}
	username, password, ok := r.BasicAuth()
	if !ok && (username != "" || password != "") {
		writeError(w, http.StatusBadRequest, "invalid authorization header")
		return
	}

	ctx := r.Context()
	response, err := h.artifactService.GetImageMetadata(ctx, image, username, password)

	if err != nil {
		switch {
		case errors.Is(err, console_errors.ErrImageNotFound):
			writeError(w, http.StatusNotFound, console_errors.ErrImageNotFound.Error())
		case errors.Is(err, console_errors.ErrArtifactAuthFailed):
			writeError(w, http.StatusUnauthorized, console_errors.ErrArtifactAuthFailed.Error())
		case errors.Is(err, console_errors.ErrArtifactInvalidImageURI):
			writeError(w, http.StatusBadRequest, console_errors.ErrArtifactInvalidImageURI.Error())
		case errors.Is(err, console_errors.ErrArtifactFailedToFetchImage):
			writeError(w, http.StatusInternalServerError, console_errors.ErrArtifactFailedToFetchImage.Error())
		case errors.Is(err, console_errors.ErrArtifactFailedToComputeDigest):
			writeError(w, http.StatusInternalServerError, console_errors.ErrArtifactFailedToComputeDigest.Error())
		case errors.Is(err, console_errors.ErrArtifactFailedToFetchConfig):
			writeError(w, http.StatusInternalServerError, console_errors.ErrArtifactFailedToFetchConfig.Error())
		case errors.Is(err, console_errors.ErrArtifactConnectionRefused):
			writeError(w, http.StatusServiceUnavailable, console_errors.ErrArtifactConnectionRefused.Error())
		default:
			writeError(w, http.StatusInternalServerError, console_errors.ErrFetchImageMetadataFailed.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, response)
}
