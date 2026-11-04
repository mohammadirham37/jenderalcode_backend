package config

import "testing"

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDevLoginRefusesNonLoopback(t *testing.T) {
	for _, addr := range []string{":8080", "0.0.0.0:8080", "192.0.2.10:8080", "[::]:8080", "example.invalid:80"} {
		_, err := Load(nil, env(map[string]string{"DEV_LOGIN": "1", "LISTEN_ADDR": addr}))
		if err == nil {
			t.Errorf("DEV_LOGIN with %q: expected error", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:9000", "127.0.0.2:1"} {
		if _, err := Load(nil, env(map[string]string{"DEV_LOGIN": "1", "LISTEN_ADDR": addr})); err != nil {
			t.Errorf("DEV_LOGIN with %q: %v", addr, err)
		}
	}
}

func TestDevLoginFlagAlsoChecked(t *testing.T) {
	_, err := Load([]string{"-dev-login", "-listen", "0.0.0.0:1"}, env(nil))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDefaultsAndGoogleRequired(t *testing.T) {
	if _, err := Load(nil, env(nil)); err == nil {
		t.Fatal("expected error without GOOGLE_CLIENT_ID")
	}
	c, err := Load(nil, env(map[string]string{"GOOGLE_CLIENT_ID": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != "127.0.0.1:8080" || c.DevLogin || c.TrustProxy {
		t.Fatalf("bad defaults: %+v", c)
	}
}
