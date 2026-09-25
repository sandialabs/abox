package config

import "testing"

func TestValidateSecretInjections(t *testing.T) {
	good := []SecretInjection{
		{Key: "anthropic", Host: "api.anthropic.com", Header: "x-api-key", PathPrefix: "/v1/"},
		{Key: "openai", Host: "api.openai.com", Header: "Authorization", ValuePrefix: "Bearer "},
	}
	if err := ValidateSecretInjections(good); err != nil {
		t.Fatalf("valid bindings rejected: %v", err)
	}

	cases := map[string][]SecretInjection{
		"bad key":        {{Key: "has space", Host: "api.example.com", Header: "x-api-key"}},
		"bad host":       {{Key: "k", Host: "not a host", Header: "x-api-key"}},
		"empty header":   {{Key: "k", Host: "api.example.com", Header: ""}},
		"bad header":     {{Key: "k", Host: "api.example.com", Header: "x api key"}},
		"rel prefix":     {{Key: "k", Host: "api.example.com", Header: "x-api-key", PathPrefix: "v1"}},
		"wildcard host":  {{Key: "k", Host: "*.example.com", Header: "x-api-key"}},
		"crlf in prefix": {{Key: "k", Host: "api.example.com", Header: "Authorization", ValuePrefix: "Bearer \r\n"}},
		"dup host+hdr": {
			{Key: "a", Host: "api.example.com", Header: "x-api-key"},
			{Key: "b", Host: "API.Example.com", Header: "X-Api-Key"},
		},
	}
	for name, injs := range cases {
		if err := ValidateSecretInjections(injs); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestValidateMITMExceptions(t *testing.T) {
	// Empty and valid lists (incl. a "*." entry that normalizes to the bare domain).
	if err := ValidateMITMExceptions(nil, nil); err != nil {
		t.Fatalf("empty list rejected: %v", err)
	}
	good := []string{"pinned.example.com", "*.corp.example", "münchen.de"}
	if err := ValidateMITMExceptions(good, nil); err != nil {
		t.Fatalf("valid exceptions rejected: %v", err)
	}

	// No conflict when the injection host is not covered by any exception.
	inj := []SecretInjection{{Key: "k", Host: "api.anthropic.com", Header: "x-api-key"}}
	if err := ValidateMITMExceptions([]string{"pinned.example.com"}, inj); err != nil {
		t.Fatalf("non-conflicting injection rejected: %v", err)
	}

	cases := map[string]struct {
		exceptions []string
		injections []SecretInjection
	}{
		"invalid host":           {exceptions: []string{"not a host"}},
		"double wildcard":        {exceptions: []string{"*.*.example.com"}},
		"embedded wildcard":      {exceptions: []string{"a.*.example.com"}},
		"duplicate":              {exceptions: []string{"example.com", "example.com"}},
		"duplicate via wildcard": {exceptions: []string{"example.com", "*.example.com"}},
		"duplicate via IDN":      {exceptions: []string{"münchen.de", "xn--mnchen-3ya.de"}},
		"conflict exact":         {exceptions: []string{"api.anthropic.com"}, injections: []SecretInjection{{Key: "k", Host: "api.anthropic.com", Header: "x-api-key"}}},
		"conflict via suffix":    {exceptions: []string{"anthropic.com"}, injections: []SecretInjection{{Key: "k", Host: "api.anthropic.com", Header: "x-api-key"}}},
		"conflict via wildcard":  {exceptions: []string{"*.anthropic.com"}, injections: []SecretInjection{{Key: "k", Host: "api.anthropic.com", Header: "x-api-key"}}},
	}
	for name, tc := range cases {
		if err := ValidateMITMExceptions(tc.exceptions, tc.injections); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
