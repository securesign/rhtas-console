package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/securesign/rhtas-console/internal/services"
)

func RegisterRoutes(r *chi.Mux, as services.ArtifactService, rs services.RekorService, ts services.TrustService) {
	handler := NewHandler(as, rs, ts)

	r.Get("/healthz", handler.GetHealthz)
	r.Post("/api/v1/artifacts/sign", handler.PostApiV1ArtifactsSign)
	r.Post("/api/v1/artifacts/verify", handler.PostApiV1ArtifactsVerify)
	r.Get("/api/v1/artifacts/{artifact}/policies", handler.GetApiV1ArtifactsArtifactPolicies)
	r.Get("/api/v1/rekor/entries/{uuid}", handler.GetApiV1RekorEntriesUuid)
	r.Get("/api/v1/rekor/public-key", handler.GetApiV1RekorPublicKey)
	r.Get("/api/v1/trust/config", handler.GetApiV1TrustConfig)
}
