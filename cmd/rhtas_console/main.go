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
	serverPort     = flag.Int("port", 8080, "RHTAS console server port")
	tlsCertFile    = flag.String("tls-cert", "", "Path to TLS certificate file")
	tlsKeyFile     = flag.String("tls-key", "", "Path to TLS private key file")
	mysqlURI       = flag.String("mysql-uri", "", "MySQL connection URI")
	postgresqlURI  = flag.String("postgresql-uri", "", "PostgreSQL connection URI")
	dbTLSCA        = flag.String("db-tls-ca", "", "Path to database TLS CA certificate")
	dbTLSServer    = flag.String("db-tls-server-name", "", "Database TLS server name for validation")
	tufRepoURL     = flag.String("tuf-repo-url", "", "TUF repository URL")
	tufRefreshInt  = flag.Duration("tuf-refresh-interval", 1*time.Minute, "TUF refresh interval")
)

func main() {

	flag.Parse()

	// Pass flags to trust service
	trustFlags := &services.TrustServiceFlags{
		MySQLURI:        *mysqlURI,
		PostgreSQLURI:   *postgresqlURI,
		TLSCA:           *dbTLSCA,
		TLSServerName:   *dbTLSServer,
		TUFRepoURL:      *tufRepoURL,
		RefreshInterval: *tufRefreshInt,
	}

	artifactService := services.NewArtifactService(*tufRepoURL)
	rekorService := services.NewRekorService()
	trustService := services.NewTrustService(trustFlags)

	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
	}))

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			req.Body = http.MaxBytesReader(w, req.Body, 1<<20)
			next.ServeHTTP(w, req)
		})
	})

	api.RegisterRoutes(r, artifactService, rekorService, trustService)

	server := &http.Server{
		Addr:              ":" + strconv.Itoa(*serverPort),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		log.Printf("Starting server on %s", server.Addr)

		var err error
		if *tlsCertFile != "" && *tlsKeyFile != "" {
			log.Printf("TLS enabled: cert=%s, key=%s", *tlsCertFile, *tlsKeyFile)
			err = server.ListenAndServeTLS(*tlsCertFile, *tlsKeyFile)
		} else {
			log.Println("TLS not configured, serving HTTP")
			err = server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
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
