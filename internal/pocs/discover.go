package pocs

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Discover 递归发现疑似 nuclei 模板的 yaml 文件（跳过 .git）。
// 仅当文件头部（前 4KB）同时含顶层 "id:" 与 "info:" 键时才视为模板，
// 剔除 README / docker-compose / CI 等 YAML 杂项。
func Discover(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 单文件/目录访问失败时容忍并继续
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}
		if looksLikeTemplate(path) {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func looksLikeTemplate(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	head := string(buf[:n])
	hasID := strings.HasPrefix(head, "id:") || strings.Contains(head, "\nid:")
	hasInfo := strings.Contains(head, "\ninfo:") || strings.HasPrefix(head, "info:")
	return hasID && hasInfo
}
