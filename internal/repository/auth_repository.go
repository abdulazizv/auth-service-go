package repository

import (
	"context"
	"database/sql"

	"authservice/internal/models"
)

type AuthRepository interface {
	CreateUser(ctx context.Context, user *models.User) error
	FindUserByEmail(ctx context.Context, email string) (*models.User, error)
	FindUserByID(ctx context.Context, id int64) (*models.User, error)
	UpdateUserRefreshToken(ctx context.Context, userID int64, refreshToken string) error
}

type authRepository struct {
	db *sql.DB
}

func NewAuthRepository(db *sql.DB) AuthRepository {
	return &authRepository{db: db}
}

func (r *authRepository) CreateUser(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (name, email, password, role_id)
		VALUES ($1, $2, $3, $4)
		RETURNING id`

	err := r.db.QueryRowContext(
		ctx,
		query,
		user.Name,
		user.Email,
		user.Password,
		user.RoleID,
	).Scan(&user.ID)

	if err != nil {
		return err
	}

	return nil
}

func (r *authRepository) FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, name, email, password, role_id, refresh_token
		FROM users
		WHERE email = $1`

	user := &models.User{}
	var refreshToken sql.NullString
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Password,
		&user.RoleID,
		&refreshToken,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, err
	}

	if refreshToken.Valid {
		user.RefreshToken = refreshToken.String
	}

	return user, nil
}

func (r *authRepository) FindUserByID(ctx context.Context, id int64) (*models.User, error) {
	query := `
		SELECT id, name, email, password, role_id, refresh_token
		FROM users
		WHERE id = $1`

	user := &models.User{}
	var refreshToken sql.NullString
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Password,
		&user.RoleID,
		&refreshToken,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		return nil, err
	}

	if refreshToken.Valid {
		user.RefreshToken = refreshToken.String
	}

	return user, nil
}

func (r *authRepository) UpdateUserRefreshToken(ctx context.Context, userID int64, refreshToken string) error {
	query := `
		UPDATE users
		SET refresh_token = $1
		WHERE id = $2`

	result, err := r.db.ExecContext(ctx, query, refreshToken, userID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}
