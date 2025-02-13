package auth

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidateJWT(t *testing.T) {
	uuid1, _ := uuid.Parse("93299465-d5c9-4165-ace6-b31cfa36b094")
	uuid2, _ := uuid.Parse("0268863e-b7f1-4b3a-80b4-32d718bba6a9")
	uuid3, _ := uuid.Parse("86239d3f-b6d6-42a7-9ac3-14b89574c7b8")

	tokens := make([]string, 3)
	foundUUIDs := make([]uuid.UUID, 3)

	cases := []struct {
		userID      uuid.UUID
		tokenSecret string
		expiresIn   time.Duration
	}{
		{
			userID:      uuid1,
			tokenSecret: "abcdefg",
			expiresIn:   24 * time.Hour,
		},
		{
			userID:      uuid2,
			tokenSecret: "12345",
			expiresIn:   24 * time.Hour,
		},
		{
			userID:      uuid3,
			tokenSecret: "9999999999999999",
			expiresIn:   24 * time.Hour,
		},
	}

	for i, c := range cases {
		actual, err := MakeJWT(c.userID, c.tokenSecret, c.expiresIn)
		if err != nil {
			t.Log("Error creating JWT")
		}
		tokens[i] = actual
		t.Logf("\nCase %d - JWT: %v\n\n", i, actual)
	}

	t.Log("\n\n------------------------------\n\n")

	for i, token := range tokens {
		actual, err := ValidateJWT(token, cases[i].tokenSecret)
		if err != nil {
			t.Log("Error validating JWT")
		}
		foundUUIDs[i] = actual
		t.Logf("\nUserID for %d is %s\n\n", i, actual)
	}
}

func TestGetBearerToken(t *testing.T) {
	cases := []struct {
		input       string
		expected    string
		expectedErr error
	}{
		{
			input:       "Bearer 12345",
			expected:    "12345",
			expectedErr: nil,
		},
		{
			input:       "54321",
			expected:    "",
			expectedErr: errors.New("auth header does not include 'Bearer '"),
		},
		{
			input:       "",
			expected:    "",
			expectedErr: errors.New("no authorization header"),
		},
	}

	for _, c := range cases {
		headers := http.Header{}
		headers.Set("Authorization", c.input)

		result, err := GetBearerToken(headers)

		if c.expectedErr != nil {
			if err == nil || err.Error() != c.expectedErr.Error() {
				t.Errorf("Expected error '%v', got '%v'", c.expectedErr, err)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		}

		if result != c.expected {
			t.Errorf("\n\nExpected '%s', got '%s'", c.expected, result)
		}
	}
}
