package config

import "testing"

func TestBackendString(t *testing.T) {
	inst := &Instance{BackendConfig: map[string]any{
		BackendKeyUUID: "abc",
		"num":          42,
		"empty":        "",
	}}

	if s, ok := inst.BackendString(BackendKeyUUID); !ok || s != "abc" {
		t.Errorf("BackendString(uuid) = %q,%v; want abc,true", s, ok)
	}
	if s, ok := inst.BackendString("empty"); !ok || s != "" {
		t.Errorf("BackendString(empty) = %q,%v; want \"\",true", s, ok)
	}
	if s, ok := inst.BackendString("num"); ok || s != "" {
		t.Errorf("BackendString(num) = %q,%v; want \"\",false (non-string)", s, ok)
	}
	if s, ok := inst.BackendString("missing"); ok || s != "" {
		t.Errorf("BackendString(missing) = %q,%v; want \"\",false", s, ok)
	}
	// nil-safe on nil map and nil receiver.
	if s, ok := (&Instance{}).BackendString("x"); ok || s != "" {
		t.Errorf("BackendString on nil map = %q,%v; want \"\",false", s, ok)
	}
	var nilInst *Instance
	if s, ok := nilInst.BackendString("x"); ok || s != "" {
		t.Errorf("BackendString on nil receiver = %q,%v; want \"\",false", s, ok)
	}
}

// TestBackendInt covers the latent bug this refactor fixes: a numeric value may
// arrive as int (YAML) or float64 (JSON round-trip). Both must read identically.
func TestBackendInt(t *testing.T) {
	cases := []struct {
		name string
		val  any
		want int
		ok   bool
	}{
		{"int", 8080, 8080, true},
		{"int64", int64(8080), 8080, true},
		{"float64 (JSON round-trip)", float64(8080), 8080, true},
		{"float32", float32(8080), 8080, true},
		{"float64 truncates", float64(8080.9), 8080, true},
		{"string is not numeric", "8080", 0, false},
		{"bool is not numeric", true, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst := &Instance{BackendConfig: map[string]any{BackendKeyRESTPort: tc.val}}
			got, ok := inst.BackendInt(BackendKeyRESTPort)
			if got != tc.want || ok != tc.ok {
				t.Errorf("BackendInt(%v) = %d,%v; want %d,%v", tc.val, got, ok, tc.want, tc.ok)
			}
		})
	}
	if got, ok := inst().BackendInt("missing"); ok || got != 0 {
		t.Errorf("BackendInt(missing) = %d,%v; want 0,false", got, ok)
	}
}

func TestBackendBool(t *testing.T) {
	inst := &Instance{BackendConfig: map[string]any{BackendKeyCustomTemplate: true}}
	if b, ok := inst.BackendBool(BackendKeyCustomTemplate); !ok || !b {
		t.Errorf("BackendBool(custom_template) = %v,%v; want true,true", b, ok)
	}
	inst.BackendConfig[BackendKeyCustomTemplate] = "yes" // non-bool
	if b, ok := inst.BackendBool(BackendKeyCustomTemplate); ok || b {
		t.Errorf("BackendBool(non-bool) = %v,%v; want false,false", b, ok)
	}
	if b, ok := (&Instance{}).BackendBool("x"); ok || b {
		t.Errorf("BackendBool on nil map = %v,%v; want false,false", b, ok)
	}
}

func inst() *Instance { return &Instance{BackendConfig: map[string]any{}} }
