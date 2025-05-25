package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq" // PostgreSQL driver
	"go.uber.org/fx"

	_ "authservice/docs" // This is where swagger docs will be generated
	"authservice/internal/api"
	"authservice/internal/api/handlers"
	"authservice/internal/api/middleware"
	"authservice/internal/auth"
	"authservice/internal/config"
	"authservice/internal/repository"
)

// @title Authentication Service API
// @version 1.0
// @description This is a sample authentication service with JWT tokens.
// @BasePath /api
// @schemes http https
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func NewGinEngine() *gin.Engine {
	return gin.Default()
}

func NewDatabaseConnection(config *config.Config) (*sql.DB, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		config.DBHost,
		config.DBPort,
		config.DBUser,
		config.DBPassword,
		config.DBName,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	return db, nil
}

func main() {

	app := fx.New(
		fx.Provide(
			config.NewConfig,
			NewDatabaseConnection,
			repository.NewAuthRepository,
			auth.NewAuthService,
			handlers.NewAuthHandler,
			NewGinEngine,
		),
		fx.Invoke(
			middleware.SetupMiddleware,
			api.NewRouter,
			registerHooks,
		),
	)

	app.Run()
}

func registerHooks(
	lifecycle fx.Lifecycle,
	ginEngine *gin.Engine,
	config *config.Config,
	db *sql.DB,
) {
	lifecycle.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				go func() {
					addr := net.JoinHostPort(config.Host, config.Port)
					log.Printf("Starting server on %s", addr)
					if err := ginEngine.Run(addr); err != nil && err != http.ErrServerClosed {
						log.Fatalf("Failed to start server: %v", err)
					}
				}()
				return nil
			},
			OnStop: func(ctx context.Context) error {
				log.Println("Shutting down server")
				if err := db.Close(); err != nil {
					log.Printf("Error closing database connection: %v", err)
				}
				return nil
			},
		},
	)
}
