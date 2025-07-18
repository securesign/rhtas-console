package main

import (
	"flag"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/securesign/rhtas-console/internal/api"
	"github.com/securesign/rhtas-console/internal/services"
)

var (
	serverPort = flag.Int("port", 8080, "RHTAS console server port")
)

func main() {

	flag.Parse()
	artifactService := services.NewArtifactService()
	rekorService := services.NewRekorService()
	trustService := services.NewTrustService()

	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
	}))

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	api.RegisterRoutes(r, artifactService, rekorService, trustService)

	portStr := strconv.Itoa(*serverPort)
	addr := ":" + portStr
	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
