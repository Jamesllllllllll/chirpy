-- +goose Up
ALTER TABLE chirps
ADD imageURL TEXT NOT NULL DEFAULT '';


-- +goose Down
ALTER TABLE chirps
DROP imageURL;