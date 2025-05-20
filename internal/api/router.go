package api

import (
	"authservice/internal/api/handlers"
	"authservice/internal/api/middleware"
	"authservice/internal/auth"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// NewRouter sets up the routing for our application
func NewRouter(engine *gin.Engine, authHandler handlers.AuthHandler, authService auth.Auth) *gin.Engine {
	// Swagger documentation
	engine.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// API routes group
	api := engine.Group("/api")
	{
		// Auth routes
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/logout", middleware.AuthMiddleware(authService), authHandler.Logout)
			auth.POST("/refresh", authHandler.RefreshToken)
		}

		// TODO: Add middleware for authenticated routes if needed
	}

	return engine
}
