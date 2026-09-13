package target

import "testing"

func TestIsTCP(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1.2.3.4:6379", true},
		{"redis.example.com:6379", true},
		{"[::1]:6379", true},
		{"http://1.2.3.4:6379", false},
		{"https://example.com", false},
		{"example.com", false},
		{"1.2.3.4", false},
		{"", false},
		{"1.2.3.4:abc", false},
		{":6379", false},
		{"127.0.0.1:", false},
	}
	for _, c := range cases {
		if got := IsTCP(c.in); got != c.want {
			t.Errorf("IsTCP(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	// TCP 目标原样保留
	got, err := NormalizeURL("1.2.3.4:6379")
	if err != nil || got != "1.2.3.4:6379" {
		t.Errorf("TCP target: got %q, err %v", got, err)
	}
	// 无 scheme 无端口补 http://（现状行为）
	got, err = NormalizeURL("example.com")
	if err != nil || got != "http://example.com" {
		t.Errorf("bare host: got %q, err %v", got, err)
	}
	// 有 scheme 不动
	got, err = NormalizeURL("https://example.com/path/")
	if err != nil || got != "https://example.com/path" {
		t.Errorf("scheme url: got %q, err %v", got, err)
	}
	// 空值报错
	if _, err = NormalizeURL("  "); err == nil {
		t.Error("empty should error")
	}
}

func TestHostKey(t *testing.T) {
	cases := []struct{ in, want string }{
		// TCP 目标：小写原样，不加 scheme
		{"1.2.3.4:6379", "1.2.3.4:6379"},
		{"Redis.Example.COM:6379", "redis.example.com:6379"},
		// HTTP 目标：补默认端口
		{"http://example.com", "http://example.com:80"},
		{"https://example.com", "https://example.com:443"},
		{"http://example.com:8080", "http://example.com:8080"},
		{"example.com", "http://example.com:80"},
	}
	for _, c := range cases {
		if got := HostKey(c.in); got != c.want {
			t.Errorf("HostKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
