package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/poly-workshop/auth-portal/configs"
	"github.com/poly-workshop/auth-portal/pkg/proto"
	"github.com/poly-workshop/go-webmods/app"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func init() {
	cwd, _ := os.Getwd()
	app.SetCMDName("gateway_server")
	app.Init(cwd)
}

// Gateway wraps the grpc-gateway mux and provides HTTP endpoints for gRPC services
type Gateway struct {
	mux       *runtime.ServeMux
	grpcConn  *grpc.ClientConn
	staticDir string
	apiPrefix string
}

// NewGateway creates a new gateway instance
func NewGateway(grpcEndpoint, staticDir, apiPrefix string) (*Gateway, error) {
	// Create gRPC connection
	conn, err := grpc.NewClient(grpcEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}

	// Create gateway mux with custom options
	mux := runtime.NewServeMux(
		runtime.WithIncomingHeaderMatcher(func(key string) (string, bool) {
			switch key {
			case "Authorization":
				return key, true
			case "X-Request-Id":
				return key, true
			default:
				return "", false
			}
		}),
		runtime.WithOutgoingHeaderMatcher(func(key string) (string, bool) {
			switch key {
			case "X-Request-Id":
				return key, true
			default:
				return "", false
			}
		}),
	)

	// Register services
	ctx := context.Background()
	if err := proto.RegisterUserServiceHandler(ctx, mux, conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to register user service handler: %w", err)
	}

	if err := proto.RegisterAuthServiceHandler(ctx, mux, conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to register auth service handler: %w", err)
	}

	return &Gateway{
		mux:       mux,
		grpcConn:  conn,
		staticDir: staticDir,
		apiPrefix: apiPrefix,
	}, nil
}

// Handler returns an HTTP handler with CORS support and static file serving
func (g *Gateway) Handler() http.Handler {
	// Setup CORS
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"}, // In production, specify your frontend domains
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Accept",
			"Accept-Language",
			"Content-Language",
			"Content-Type",
			"Authorization",
			"X-Request-Id",
		},
		ExposedHeaders: []string{
			"X-Request-Id",
		},
		AllowCredentials: true,
	})

	// Create a multiplexer that handles both API and static files
	mux := http.NewServeMux()

	// Handle API routes with the gRPC gateway
	mux.Handle(g.apiPrefix, http.StripPrefix(strings.TrimSuffix(g.apiPrefix, "/"), g.mux))

	// Handle static files for the frontend
	if g.staticDir != "" {
		// Check if static directory exists
		if _, err := os.Stat(g.staticDir); err == nil {
			// Serve static files, with index.html as fallback for SPA
			fileServer := http.FileServer(http.Dir(g.staticDir))
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				// Check if the requested file exists
				path := filepath.Join(g.staticDir, r.URL.Path)
				if _, err := os.Stat(path); os.IsNotExist(err) {
					// If file doesn't exist and it's not an API request, serve index.html for SPA routing
					if !strings.HasPrefix(r.URL.Path, strings.TrimSuffix(g.apiPrefix, "/")) {
						http.ServeFile(w, r, filepath.Join(g.staticDir, "index.html"))
						return
					}
				}
				fileServer.ServeHTTP(w, r)
			})
			slog.Info("Static file serving enabled", "directory", g.staticDir)
		} else {
			slog.Warn("Static directory not found, serving API only", "directory", g.staticDir)
			// If static directory doesn't exist, just serve the API
			mux.Handle("/", g.mux)
		}
	} else {
		// If no static directory specified, just serve the API
		mux.Handle("/", g.mux)
	}

	return c.Handler(mux)
}

// Close closes the gRPC connection
func (g *Gateway) Close() error {
	if g.grpcConn != nil {
		return g.grpcConn.Close()
	}
	return nil
}

func main() {
	cfg := configs.Load()

	// Get current working directory to locate frontend dist
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("failed to get current working directory: %v", err)
	}

	// Static directory path (relative to project root)
	staticDir := filepath.Join(cwd, "frontend", "dist")
	apiPrefix := "/api/"

	// Create gateway instance
	grpcEndpoint := fmt.Sprintf("localhost:%d", cfg.Server.Port)
	gateway, err := NewGateway(grpcEndpoint, staticDir, apiPrefix)
	if err != nil {
		log.Fatalf("failed to create gateway: %v", err)
	}
	defer func() { _ = gateway.Close() }()

	// Create HTTP server
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		Handler: gateway.Handler(),
	}

	slog.Info("HTTP gateway server started",
		"port", cfg.Server.HTTPPort,
		"grpc_endpoint", grpcEndpoint,
		"static_dir", staticDir,
		"api_prefix", apiPrefix)

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("failed to serve HTTP: %v", err)
	}
}
