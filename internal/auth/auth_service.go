package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"authservice/internal/config"
	"authservice/internal/models"
	"authservice/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrUserAlreadyExists  = errors.New("user with this email already exists")
)

var cfg = config.NewConfig()
var jwtSigningKey = []byte(cfg.SecretKey)

const (
	accessTokenDuration  = time.Minute * 15
	refreshTokenDuration = time.Hour * 24 * 7
)

type Auth interface {
	Register(ctx context.Context, name, email, password string, roleID int64) (*models.User, string, string, error)
	Login(ctx context.Context, email, password string) (*models.User, string, string, error)
	Logout(ctx context.Context, userID int64) error
	RefreshToken(ctx context.Context, refreshToken string) (*models.User, string, string, error)
}

type authService struct {
	repo repository.AuthRepository
}

func NewAuthService(repo repository.AuthRepository) Auth {
	return &authService{repo: repo}
}

func (s *authService) Register(ctx context.Context, name, email, password string, roleID int64) (*models.User, string, string, error) {
	existingUser, err := s.repo.FindUserByEmail(ctx, email)
	if err != nil && err != sql.ErrNoRows {
		return nil, "", "", fmt.Errorf("failed to check for existing user: %w", err)
	}
	if existingUser != nil {
		return nil, "", "", ErrUserAlreadyExists
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		Name:     name,
		Email:    email,
		Password: string(hashedPassword),
		RoleID:   roleID,
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, "", "", fmt.Errorf("failed to create user: %w", err)
	}

	accessToken, err := generateAccessToken(user)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := generateRefreshToken(user.ID)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	if err := s.repo.UpdateUserRefreshToken(ctx, user.ID, refreshToken); err != nil {
		return nil, "", "", fmt.Errorf("failed to update refresh token: %w", err)
	}

	return user, accessToken, refreshToken, nil
}

func (s *authService) Login(ctx context.Context, email, password string) (*models.User, string, string, error) {
	user, err := s.repo.FindUserByEmail(ctx, email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", "", ErrUserNotFound
		}
		return nil, "", "", fmt.Errorf("failed to find user by email: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return nil, "", "", ErrInvalidCredentials
		}
		return nil, "", "", fmt.Errorf("failed to compare passwords: %w", err)
	}

	// Generate new Access and Refresh tokens
	accessToken, err := generateAccessToken(user)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := generateRefreshToken(user.ID)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	if err := s.repo.UpdateUserRefreshToken(ctx, user.ID, refreshToken); err != nil {
		return nil, "", "", fmt.Errorf("failed to update refresh token: %w", err)
	}

	return user, accessToken, refreshToken, nil
}

func (s *authService) Logout(ctx context.Context, userID int64) error {
	if err := s.repo.UpdateUserRefreshToken(ctx, userID, ""); err != nil {
		return fmt.Errorf("failed to clear refresh token: %w", err)
	}

	return nil
}

func (s *authService) RefreshToken(ctx context.Context, refreshToken string) (*models.User, string, string, error) {
	claims, err := ValidateToken(refreshToken)
	if err != nil {
		if err == jwt.ErrTokenExpired {
			return nil, "", "", ErrInvalidToken
		}
		return nil, "", "", fmt.Errorf("invalid refresh token: %w", err)
	}

	if claims.Type != "refresh" {
		return nil, "", "", ErrInvalidToken
	}

	user, err := s.repo.FindUserByID(ctx, claims.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", "", ErrUserNotFound
		}
		return nil, "", "", fmt.Errorf("failed to find user: %w", err)
	}

	if user.RefreshToken != refreshToken {
		return nil, "", "", ErrInvalidToken
	}

	accessToken, err := generateAccessToken(user)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshToken, err := generateRefreshToken(user.ID)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	if err := s.repo.UpdateUserRefreshToken(ctx, user.ID, newRefreshToken); err != nil {
		return nil, "", "", fmt.Errorf("failed to update refresh token: %w", err)
	}

	return user, accessToken, newRefreshToken, nil
}

type Claims struct {
	UserID int64  `json:"user_id"`
	Type   string `json:"type"` // "access" or "refresh"
	RoleID int64  `json:"role_id"`
	jwt.RegisteredClaims
}

func generateAccessToken(user *models.User) (string, error) {
	expirationTime := time.Now().Add(accessTokenDuration)
	claims := &Claims{
		UserID: user.ID,
		Type:   "access",
		RoleID: user.RoleID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   fmt.Sprintf("%d", user.ID),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSigningKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}
	return tokenString, nil
}

func generateRefreshToken(userID int64) (string, error) {
	expirationTime := time.Now().Add(refreshTokenDuration)
	claims := &Claims{
		UserID: userID,
		Type:   "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   fmt.Sprintf("%d", userID),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSigningKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}
	return tokenString, nil
}

// ValidateToken validates a JWT token and returns its claims
func ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSigningKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, ErrInvalidToken
		}
		if err == jwt.ErrTokenExpired {
			return nil, jwt.ErrTokenExpired
		}
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
