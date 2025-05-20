package middleware

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

func SetupMiddleware(engine *gin.Engine) {
	engine.Use(Logger())
	engine.Use(RequestID())
	engine.Use(Cors())
}

type Middleware struct {
	Logger    gin.HandlerFunc
	Cors      gin.HandlerFunc
	RequestID gin.HandlerFunc
}

func NewMiddleware() *Middleware {
	return &Middleware{
		Logger:    Logger(),
		Cors:      Cors(),
		RequestID: RequestID(),
	}
}

func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		startTime := time.Now()

		// Process request
		c.Next()

		// Calculate response time
		endTime := time.Now()
		latency := endTime.Sub(startTime)

		// Get request details
		method := c.Request.Method
		path := c.Request.URL.Path
		statusCode := c.Writer.Status()

		// Log request details
		log.Printf("[CUSTOM-MIDDLEWARE] %s %s | %d | %v", method, path, statusCode, latency)
	}
}

func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := time.Now().UnixNano()
		c.Set("RequestID", requestID)
		c.Writer.Header().Set("X-Request-ID", time.Now().Format("20060102150405")+"-"+c.ClientIP())
		c.Next()
	}
}
