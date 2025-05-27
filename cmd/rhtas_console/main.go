package main

import (
	"flag"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	api.RegisterRoutes(r, artifactService, rekorService, trustService)

	portStr := strconv.Itoa(*serverPort)
	addr := ":" + portStr
	log.Printf("Starting sss server on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
