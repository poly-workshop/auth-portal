package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/poly-workshop/auth-portal/configs"
	auth_v1_pb "github.com/poly-workshop/auth-portal/gen/auth/v1"
	user_v1_pb "github.com/poly-workshop/auth-portal/gen/user/v1"
	"github.com/poly-workshop/auth-portal/internal/model"
	"github.com/poly-workshop/auth-portal/internal/repository"
	"github.com/poly-workshop/auth-portal/internal/service"
	"github.com/poly-workshop/auth-portal/pkg/auth"
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
	app.SetCMDName("grpc_server")
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
	authService := service.NewAuthService(db, rdb)

	// Define public methods that don't require authentication
	publicMethods := map[string]bool{
		auth_v1_pb.AuthService_GetOAuthCodeURL_FullMethodName: true,
		auth_v1_pb.AuthService_LoginByOAuth_FullMethodName:    true,
		auth_v1_pb.AuthService_LoginByPassword_FullMethodName: true,
		auth_v1_pb.AuthService_GetUserToken_FullMethodName:    true,
	}

	// Setup gRPC server with auth interceptor
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			grpc_utils.BuildRequestIDInterceptor(),
			logging.UnaryServerInterceptor(InterceptorLogger(slog.Default())),
			auth.BuildAuthInterceptor(publicMethods, cfg.Auth.JWTSecret),
		),
	)
	user_v1_pb.RegisterUserServiceServer(grpcServer, userService)
	auth_v1_pb.RegisterAuthServiceServer(grpcServer, authService)
	reflection.Register(grpcServer)

	// Start gRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.Port))
	if err != nil {
		log.Fatalf("failed to listen on gRPC port: %v", err)
	}

	slog.Info("gRPC server started", "port", cfg.Server.Port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve gRPC: %v", err)
	}
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
