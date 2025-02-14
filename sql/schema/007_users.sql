-- +goose Up
ALTER TABLE users
SET username text NOT NULL UNIQUE
DEFAULT 'unset';

-- +goose Down
ALTER TABLE users
SET username text NOT NULL
DEFAULT 'unset';