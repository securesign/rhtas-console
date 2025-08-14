package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os/signal"
	"strconv"
	"syscall"
	"time"

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

	server := &http.Server{
		Addr:    ":" + strconv.Itoa(*serverPort),
		Handler: r,
	}

	go func() {
		log.Printf("Starting server on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Handle shutdown signals
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	log.Println("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown failed: %v", err)
	}

	if err := trustService.CloseDB(); err != nil {
		log.Printf("Failed to close trustService: %v", err)
	}

	log.Println("Server shut down successfully")
}
