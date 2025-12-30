package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"authorization_flow_oauth/pkg/auth"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	Auth        auth.Config
	RedisConfig redis.Options
	AppPort     string
	AppHost     string
}

func LoadFromEnv() (*Config, error) {
	// Get the absolute path of the current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	// Construct path to .env file in ../cmd/.env
	envPath := filepath.Join(currentDir, "..", ".env")
	err = godotenv.Load(envPath)

	if err != nil {
		log.Fatal("Error loading .env file", err)
	}

	redisDB, err := strconv.Atoi(os.Getenv("REDIS_DATABASE"))
	if err != nil {
		log.Fatal("Database redis invalid : ", err)
	}
	return &Config{
		Auth: auth.Config{
			BaseURL:      os.Getenv("AUTH_BASE_URL"),
			ClientID:     os.Getenv("AUTH_CLIENT_ID"),
			RedirectURL:  os.Getenv("AUTH_REDIRECT_URL"),
			ClientSecret: os.Getenv("AUTH_CLIENT_SECRET"),
			Realm:        os.Getenv("AUTH_ENVIRONMENT"),
		},
		RedisConfig: redis.Options{
			Addr:     fmt.Sprintf("%s:%s", os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT")),
			Username: os.Getenv("REDIS_USERNAME"),
			Password: os.Getenv("REDIS_PASSWORD"),
			DB:       redisDB,
		},
		AppPort: os.Getenv("APP_PORT"),
		AppHost: os.Getenv("APP_HOST"),
	}, nil
}
