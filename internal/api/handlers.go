package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/securesign/rhtas-console/internal/models"
	"github.com/securesign/rhtas-console/internal/services"
)

// Handler implements the ServerInterface
type Handler struct {
	artifactService services.ArtifactService
	rekorService    services.RekorService
	trustService    services.TrustService
}

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
		writeError(w, http.StatusBadRequest, "Invalid request body")
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
		writeError(w, http.StatusBadRequest, "Invalid request body")
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
		writeError(w, http.StatusBadRequest, "Missing UUID")
		return
	}
	resp, err := h.rekorService.GetRekorEntry(r.Context(), uuid)
	if err != nil {
		writeError(w, http.StatusNotFound, "Missing entry")
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
		writeError(w, http.StatusBadRequest, "Missing artifact")
		return
	}
	resp, err := h.artifactService.GetArtifactPolicies(r.Context(), artifact)
	if err != nil {
		writeError(w, http.StatusNotFound, "Artifact not found")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) GetApiV1TrustConfig(w http.ResponseWriter, r *http.Request) {
	resp, err := h.trustService.GetTrustConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, models.Error{Error: message})
}
