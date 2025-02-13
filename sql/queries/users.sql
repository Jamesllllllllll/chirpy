-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password, username)
VALUES (
    gen_random_uuid(), NOW(), NOW(), $1, $2, $3
)
RETURNING *;

-- name: FindUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: FindUserById :one
SELECT * FROM users
WHERE id = $1;

-- name: UpdateUser :one
UPDATE users
SET hashed_password = $1, email = $2, updated_at = NOW()
WHERE id = $3
RETURNING *;

-- name: DeleteUsers :exec
DELETE FROM users;

-- name: UpgradeUser :one
UPDATE users
set is_chirpy_red = true
WHERE id = $1
RETURNING *;