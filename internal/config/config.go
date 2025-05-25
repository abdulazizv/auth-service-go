package config

import (
	"os"
)

type Config struct {
	Host       string
	Port       string
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	SecretKey  string
}

func NewConfig() *Config {
	return &Config{
		Host:       getEnv("HOST", "localhost"),
		Port:       getEnv("PORT", "3001"),
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "5435"),
		DBUser:     getEnv("DB_USER", "criminalist"),
		DBPassword: getEnv("DB_PASSWORD", "criminalist"),
		DBName:     getEnv("DB_NAME", "classroom"),
		SecretKey:  getEnv("SECRET_KEY", "secret"),
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
