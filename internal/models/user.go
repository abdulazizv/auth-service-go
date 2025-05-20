package models

type User struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	Password     string `json:"-"`
	RoleID       int64  `json:"role_id"`
	RefreshToken string `json:"-"`
}

const (
	RoleAdmin   int64 = 1
	RoleMentor  int64 = 2
	RoleStudent int64 = 3
)
