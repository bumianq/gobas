package source

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRepoKey(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://github.com/projectdiscovery/nuclei-templates", "projectdiscovery/nuclei-templates"},
		{"https://github.com/adysec/nuclei_poc/", "adysec/nuclei_poc"},
		{"https://github.com/AshiqurEmon/nuclei_templates.git", "ashiquremon/nuclei_templates"},
		{"http://www.github.com/Foo/Bar", "foo/bar"},
		{"https://gist.github.com/user/gistid", ""},
		{"https://gitlab.com/foo/bar", ""},
		{"not a url", ""},
		{"https://github.com/onlyowner", ""},
	}
	for _, c := range cases {
		if got := RepoKey(c.in); got != c.want {
			t.Errorf("RepoKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLoadAndSaveSources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sources.yaml")
	srcs := []Source{
		{URL: "https://github.com/a/b", Official: false},
		{URL: "https://github.com/projectdiscovery/nuclei-templates", Official: true},
	}
	if err := SaveSources(path, srcs); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSources(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 {
		t.Fatalf("want 2 sources, got %d", len(loaded))
	}
	if !loaded[0].EnabledOrDefault() {
		t.Error("source should be enabled by default")
	}
}

func TestImportCSVAndMerge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "repo.csv")
	content := "https://github.com/projectdiscovery/nuclei-templates\n\nhttps://github.com/a/b\nhttps://github.com/a/b\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	imported, err := ImportCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(imported) != 2 {
		t.Fatalf("want 2 imported, got %d", len(imported))
	}
	if !imported[0].Official {
		t.Error("official repo should be marked")
	}
	merged := MergeSources(imported, []Source{{URL: "https://github.com/a/b"}, {URL: "https://github.com/c/d"}})
	if len(merged) != 3 {
		t.Fatalf("want 3 merged, got %d", len(merged))
	}
}
