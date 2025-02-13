// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: users.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password, username)
VALUES (
    gen_random_uuid(), NOW(), NOW(), $1, $2, $3
)
RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red, username
`

type CreateUserParams struct {
	Email          string
	HashedPassword string
	Username       string
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser, arg.Email, arg.HashedPassword, arg.Username)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
		&i.Username,
	)
	return i, err
}

const deleteUsers = `-- name: DeleteUsers :exec
DELETE FROM users
`

func (q *Queries) DeleteUsers(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteUsers)
	return err
}

const findUserByEmail = `-- name: FindUserByEmail :one
SELECT id, created_at, updated_at, email, hashed_password, is_chirpy_red, username FROM users
WHERE email = $1
`

func (q *Queries) FindUserByEmail(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRowContext(ctx, findUserByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
		&i.Username,
	)
	return i, err
}

const findUserById = `-- name: FindUserById :one
SELECT id, created_at, updated_at, email, hashed_password, is_chirpy_red, username FROM users
WHERE id = $1
`

func (q *Queries) FindUserById(ctx context.Context, id uuid.UUID) (User, error) {
	row := q.db.QueryRowContext(ctx, findUserById, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
		&i.Username,
	)
	return i, err
}

const updateUser = `-- name: UpdateUser :one
UPDATE users
SET hashed_password = $1, email = $2, updated_at = NOW()
WHERE id = $3
RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red, username
`

type UpdateUserParams struct {
	HashedPassword string
	Email          string
	ID             uuid.UUID
}

func (q *Queries) UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUser, arg.HashedPassword, arg.Email, arg.ID)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
		&i.Username,
	)
	return i, err
}

const upgradeUser = `-- name: UpgradeUser :one
UPDATE users
set is_chirpy_red = true
WHERE id = $1
RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red, username
`

func (q *Queries) UpgradeUser(ctx context.Context, id uuid.UUID) (User, error) {
	row := q.db.QueryRowContext(ctx, upgradeUser, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
		&i.Username,
	)
	return i, err
}
