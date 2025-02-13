-- +goose Up
ALTER TABLE users
ADD username text NOT NULL
DEFAULT 'unset';

ALTER TABLE chirps
ADD username TEXT NOT NULL
DEFAULT 'unset';

-- +goose Down
ALTER TABLE users
DROP username;

ALTER TABLE chirps
DROP username;