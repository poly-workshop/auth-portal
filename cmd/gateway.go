package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	protopb "github.com/poly-workshop/auth-portal/pkg/proto"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Gateway wraps the grpc-gateway mux and provides HTTP endpoints for gRPC services
type Gateway struct {
	mux      *runtime.ServeMux
	grpcConn *grpc.ClientConn
}

// NewGateway creates a new gateway instance
func NewGateway(grpcEndpoint string) (*Gateway, error) {
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
	if err := protopb.RegisterUserServiceHandler(ctx, mux, conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to register user service handler: %w", err)
	}

	if err := protopb.RegisterAuthServiceHandler(ctx, mux, conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to register auth service handler: %w", err)
	}

	return &Gateway{
		mux:      mux,
		grpcConn: conn,
	}, nil
}

// Handler returns an HTTP handler with CORS support
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

	return c.Handler(g.mux)
}

// Close closes the gRPC connection
func (g *Gateway) Close() error {
	if g.grpcConn != nil {
		return g.grpcConn.Close()
	}
	return nil
}
