package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		wantKey       string
		wantErr       error
		wantErrString string
	}{
		{
			name:       "valid API key",
			authHeader: "ApiKey abc123",
			wantKey:    "abc123",
		},
		{
			name:       "valid API key with special characters",
			authHeader: "ApiKey abc-123_XYZ",
			wantKey:    "abc-123_XYZ",
		},
		{
			name:    "missing authorization header",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "wrong authorization scheme",
			authHeader:    "Bearer abc123",
			wantErrString: "malformed authorization header",
		},
		{
			name:          "missing API key",
			authHeader:    "ApiKey",
			wantErrString: "malformed authorization header",
		},
		{
			name:       "empty API key",
			authHeader: "ApiKey ",
			wantKey:    "",
		},
		{
			name:       "extra spaces",
			authHeader: "ApiKey  abc123",
			wantKey:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			gotKey, err := GetAPIKey(headers)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
			} else if tt.wantErrString != "" {
				if err == nil || err.Error() != tt.wantErrString {
					t.Fatalf("expected error %q, got %v", tt.wantErrString, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if gotKey != tt.wantKey {
				t.Errorf("got key %q, want %q", gotKey, tt.wantKey)
			}
		})
	}
}
