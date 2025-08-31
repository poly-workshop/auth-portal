package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/poly-workshop/auth-portal/configs"
	"github.com/poly-workshop/auth-portal/internal/handler"
	"github.com/poly-workshop/auth-portal/internal/model"
	"github.com/poly-workshop/auth-portal/internal/repository"
	"github.com/poly-workshop/auth-portal/internal/service"
	"github.com/poly-workshop/auth-portal/pkg/auth"
	protopb "github.com/poly-workshop/auth-portal/pkg/proto"
	"github.com/poly-workshop/go-webmods/app"
	"github.com/poly-workshop/go-webmods/gorm_client"
	"github.com/poly-workshop/go-webmods/grpc_utils"
	"github.com/poly-workshop/go-webmods/redis_client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func init() {
	cwd, _ := os.Getwd()
	app.SetCMDName("user_service")
	app.Init(cwd)
}

// InterceptorLogger adapts slog logger to interceptor logger.
// This code is simple enough to be copied and not imported.
func InterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(
		func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
			l.Log(ctx, slog.Level(lvl), msg, fields...)
		},
	)
}

func main() {
	cfg := configs.Load()

	// Initialize database
	db := gorm_client.NewDB(cfg.Database)
	err := db.AutoMigrate(&model.UserModel{})
	if err != nil {
		slog.Error("failed to migrate database", "error", err)
	}

	// Initialize Redis client
	redis_client.SetConfig(cfg.Redis.Urls, cfg.Redis.Password)
	rdb := redis_client.GetRDB()

	// Initialize repositories and services
	userRepo := repository.NewUserRepository(db)
	userService := service.NewUserService(userRepo)
	sessionService := service.NewSessionService(rdb, cfg)
	oauthService := service.NewOAuthService(rdb, cfg)

	// Initialize handlers
	userHandler := handler.NewUserHandler(userService)
	authHandler := handler.NewAuthHandler(db, rdb, sessionService, oauthService)

	// Define public methods that don't require authentication
	publicMethods := map[string]bool{
		protopb.AuthService_GetOAuthCodeURL_FullMethodName: true,
		protopb.AuthService_LoginByOAuth_FullMethodName:    true,
		protopb.AuthService_LoginByPassword_FullMethodName: true,
		protopb.AuthService_GetUserToken_FullMethodName:    true,
	}

	// Setup gRPC server with auth interceptor
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			grpc_utils.BuildRequestIDInterceptor(),
			logging.UnaryServerInterceptor(InterceptorLogger(slog.Default())),
			auth.BuildAuthInterceptor(publicMethods, cfg.Auth.JWTSecret),
		),
	)
	protopb.RegisterUserServiceServer(grpcServer, userHandler)
	protopb.RegisterAuthServiceServer(grpcServer, authHandler)
	reflection.Register(grpcServer)

	// Start gRPC server in a goroutine
	var wg sync.WaitGroup
	wg.Add(2)

	// Start gRPC server
	go func() {
		defer wg.Done()
		lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.Port))
		if err != nil {
			log.Fatalf("failed to listen on gRPC port: %v", err)
		}
		slog.Info("gRPC server started", "port", cfg.Server.Port)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve gRPC: %v", err)
		}
	}()

	// Start HTTP Gateway server
	go func() {
		defer wg.Done()

		// Create gateway instance
		grpcEndpoint := fmt.Sprintf("localhost:%d", cfg.Server.Port)
		gw, err := NewGateway(grpcEndpoint)
		if err != nil {
			log.Fatalf("failed to create gateway: %v", err)
		}
		defer func() { _ = gw.Close() }()

		// Create HTTP server
		httpServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.Server.HTTPPort),
			Handler: gw.Handler(),
		}

		slog.Info("HTTP gateway server started", "port", cfg.Server.HTTPPort)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("failed to serve HTTP: %v", err)
		}
	}()

	// Wait for both servers
	wg.Wait()
}

func NewDB(cfg configs.Config) *gorm.DB {
	driver := cfg.Database.Driver
	switch driver {
	case "postgres":
		db, err := openPostgres(cfg)
		if err != nil {
			panic(err)
		}
		return db
	default:
		panic(fmt.Sprintf("unsupported database driver: %s", driver))
	}
}

func openPostgres(cfg configs.Config) (db *gorm.DB, err error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s dbname=%s password=%s sslmode=%s",
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Username,
		cfg.Database.Name,
		cfg.Database.Password,
		cfg.Database.SSLMode,
	)
	db, err = gorm.Open(postgres.Open(dsn))
	if err != nil {
		return nil, err
	}
	return db, nil
}
