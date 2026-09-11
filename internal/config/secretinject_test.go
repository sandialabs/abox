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
