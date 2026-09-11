package validation

import "testing"

func TestValidateSecretKey(t *testing.T) {
	for _, ok := range []string{"anthropic", "OPENAI", "_x", "a1_b2", "K"} {
		if err := ValidateSecretKey(ok); err != nil {
			t.Errorf("ValidateSecretKey(%q) unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "1leading", "has space", "has-dash", "dots.here", "nl\nkey", "tab\tkey"} {
		if err := ValidateSecretKey(bad); err == nil {
			t.Errorf("ValidateSecretKey(%q) should have failed", bad)
		}
	}
}

func TestValidateHTTPHeaderName(t *testing.T) {
	for _, ok := range []string{"x-api-key", "Authorization", "X-Custom_Header", "a"} {
		if err := ValidateHTTPHeaderName(ok); err != nil {
			t.Errorf("ValidateHTTPHeaderName(%q) unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "x api key", "x\r\ny", "colon:name", "nl\n"} {
		if err := ValidateHTTPHeaderName(bad); err == nil {
			t.Errorf("ValidateHTTPHeaderName(%q) should have failed", bad)
		}
	}
}

func TestValidateHTTPHeaderValue(t *testing.T) {
	for _, ok := range []string{"", "sk-ant-123", "Bearer tok", "with\ttab", "spaces are fine"} {
		if err := ValidateHTTPHeaderValue(ok); err != nil {
			t.Errorf("ValidateHTTPHeaderValue(%q) unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{"a\rb", "a\nb", "a\x00b", "a\x7fb", "trailing\n"} {
		if err := ValidateHTTPHeaderValue(bad); err == nil {
			t.Errorf("ValidateHTTPHeaderValue(%q) should have failed", bad)
		}
	}
	// The error must not include the offending byte itself (it validates
	// secret-derived values and is logged) — only an offset.
	if err := ValidateHTTPHeaderValue("ok\nbad"); err != nil {
		if got := err.Error(); !contains(got, "offset") || contains(got, "0x") {
			t.Errorf("error should report offset, not the byte: %q", got)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
