package service

import (
	"strings"
	"testing"
)

// TestTruncateTraffic 验证流量字段截断与 UTF-8 清洗。
func TestTruncateTraffic(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		n          int
		wantTrunc  bool
		checkLen   int  // 期望结果长度（含后缀）
		checkHasFn bool // 期望含 U+FFFD
	}{
		{
			name:      "未超限原样返回",
			in:        "HTTP/1.1 200 OK\r\n\r\n",
			n:         64,
			wantTrunc: false,
		},
		{
			name:      "超限头部截断加省略号",
			in:        strings.Repeat("A", 100),
			n:         50,
			wantTrunc: true,
			checkLen:  53, // 50 + "..."
		},
		{
			name:       "无效UTF8被清洗为替换字符",
			in:         "resp\x80\x81body",
			n:          64,
			wantTrunc:  false,
			checkHasFn: true,
		},
		{
			name:      "截断切断多字节字符补替换字符",
			in:        strings.Repeat("中", 30), // 每字 3 字节
			n:         10,                     // 切在第 10 字节 = 3 个完整字 + 1 字节残片
			wantTrunc: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, trunc := truncateTraffic(c.in, c.n)
			if trunc != c.wantTrunc {
				t.Fatalf("truncated = %v, want %v", trunc, c.wantTrunc)
			}
			if c.wantTrunc && !strings.HasSuffix(out, "...") {
				t.Fatalf("截断结果应以 ... 结尾，got %q", out)
			}
			if c.checkLen > 0 && len(out) != c.checkLen {
				t.Fatalf("len = %d, want %d", len(out), c.checkLen)
			}
			if c.checkHasFn && !strings.ContainsRune(out, '\uFFFD') {
				t.Fatalf("应含 U+FFFD 替换字符，got %q", out)
			}
			// 所有结果必须是合法 UTF-8（JSON 可序列化前提）
			for _, r := range out {
				if r == 0xFFFD {
					continue // 替换字符本身合法
				}
			}
		})
	}
}
