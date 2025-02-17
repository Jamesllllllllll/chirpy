-- +goose Up
ALTER TABLE users
DROP CONSTRAINT IF EXISTS users_username_key;

ALTER TABLE users
ALTER COLUMN username SET NOT NULL;

ALTER TABLE users
ADD CONSTRAINT users_username_unique UNIQUE (username);

-- +goose Down
ALTER TABLE users
DROP CONSTRAINT IF EXISTS users_username_unique;