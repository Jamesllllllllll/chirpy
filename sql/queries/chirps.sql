-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(), NOW(), NOW(), $1, $2
)
RETURNING *;

-- name: DeleteAllChirps :exec
TRUNCATE chirps;

-- name: GetAllChirps :many
SELECT * FROM chirps
ORDER BY created_at ASC;

-- name: GetChirpsByAuthor :many
SELECT * FROM chirps
WHERE user_id = $1
ORDER BY created_at ASC;

-- name: GetSingleChirp :one
SELECT * FROM chirps
WHERE ID = $1;

-- name: DeleteSingleChrip :exec
DELETE FROM chirps
WHERE ID = $1;