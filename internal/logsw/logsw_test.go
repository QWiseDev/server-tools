package logsw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"servermcp/internal/config"
)

func newTestManager(t *testing.T, dir string) *Manager {
	t.Helper()
	return NewManager(&config.Config{LogDirs: []string{dir}, MaxOutput: 100000})
}

// writeLogFile 生成 n 行日志，并在指定行号（1-based）插入标记行。
func writeLogFile(t *testing.T, dir string, n int, markers map[int]string) string {
	t.Helper()
	p := filepath.Join(dir, "app.log")
	var b strings.Builder
	for i := 1; i <= n; i++ {
		if m, ok := markers[i]; ok {
			b.WriteString(m + "\n")
			continue
		}
		b.WriteString("line: filler info\n")
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSearchPaginationAndLineNumbers(t *testing.T) {
	dir := t.TempDir()
	m := newTestManager(t, dir)
	p := writeLogFile(t, dir, 100, map[int]string{
		5:   "line5: ERROR first",
		50:  "line50: ERROR second",
		100: "line100: error third",
	})

	// 每页 1 条翻页，行号必须与全文件对齐
	var got []int
	var offset int64
	pages := 0
	for {
		res, err := m.Search(p, "ERROR", 1, offset, false)
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		for _, match := range res.Matches {
			got = append(got, match.Line)
		}
		pages++
		if res.Complete {
			break
		}
		if res.NextOffset <= offset {
			t.Fatalf("next_offset 未前进: %d -> %d", offset, res.NextOffset)
		}
		offset = res.NextOffset
		if pages > 10 {
			t.Fatal("翻页未收敛")
		}
	}
	if len(got) != 2 || got[0] != 5 || got[1] != 50 {
		t.Fatalf("命中行号 = %v, want [5 50]", got)
	}

	// ci 命中第三条（小写 error）
	res, err := m.Search(p, "error", 10, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	var ciLines []int
	for _, match := range res.Matches {
		ciLines = append(ciLines, match.Line)
	}
	if len(ciLines) != 3 || ciLines[2] != 100 {
		t.Fatalf("ci 命中 = %v, want [5 50 100]", ciLines)
	}

	// 区分大小写只命中小写那条（line 100）
	res, _ = m.Search(p, "error", 10, 0, false)
	if len(res.Matches) != 1 || res.Matches[0].Line != 100 {
		t.Fatalf("区分大小写命中 = %+v, want [100]", res.Matches)
	}
}

func TestSearchRegexAndErrors(t *testing.T) {
	dir := t.TempDir()
	m := newTestManager(t, dir)
	p := writeLogFile(t, dir, 10, map[int]string{3: "req-42 done", 7: "req-99 done"})

	res, err := m.Search(p, `/req-(42|99)/`, 10, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 2 {
		t.Fatalf("正则命中 %d 条, want 2", len(res.Matches))
	}
	if _, err := m.Search(p, "/[/", 10, 0, false); err == nil {
		t.Fatal("非法正则应报错")
	}
	if _, err := m.Search(p, "", 10, 0, false); err == nil {
		t.Fatal("空模式应报错")
	}
	if _, err := m.Search("/etc/passwd", "root", 10, 0, false); err == nil {
		t.Fatal("白名单外路径应报错")
	}
	if _, err := m.Search("docker:foo", "x", 10, 0, false); err == nil {
		t.Fatal("docker 来源应报错")
	}
	// offset 超出文件大小 → 直接完成
	res, err = m.Search(p, "x", 10, 1<<30, false)
	if err != nil || !res.Complete || len(res.Matches) != 0 {
		t.Fatalf("超大 offset: res=%+v err=%v", res, err)
	}
}

func TestBuildMatcher(t *testing.T) {
	sub, err := buildMatcher("abc", false)
	if err != nil {
		t.Fatal(err)
	}
	if !sub([]byte("xx abc yy")) || sub([]byte("abd")) {
		t.Fatal("子串匹配错误")
	}
	ciSub, _ := buildMatcher("AbC", true)
	if !ciSub([]byte("xabc")) {
		t.Fatal("ci 子串应命中小写")
	}
	re, _ := buildMatcher("/^a+c$/", true)
	if !re([]byte("aaac")) || re([]byte("aaad")) {
		t.Fatal("正则匹配错误")
	}
	if _, err := buildMatcher("/(/", false); err == nil {
		t.Fatal("非法正则应报错")
	}
}

func TestTailLinesAndAllowed(t *testing.T) {
	dir := t.TempDir()
	m := newTestManager(t, dir)
	p := writeLogFile(t, dir, 1000, map[int]string{1000: "last line"})

	lines := tailLines(p, 10)
	if len(lines) != 10 || lines[len(lines)-1] != "last line" {
		t.Fatalf("tail 10 行错误: 首行=%q 末行=%q", lines[0], lines[len(lines)-1])
	}

	if _, err := m.allowed("/etc/passwd"); err == nil {
		t.Fatal("白名单外应拒绝")
	}
	// macOS 的 /var 是软链：放行返回的是 realpath
	rpWant, _ := filepath.EvalSymlinks(p)
	if rp, err := m.allowed(p); err != nil || rp != rpWant {
		t.Fatalf("白名单内应放行: rp=%q want=%q err=%v", rp, rpWant, err)
	}
}

func TestFilterLines(t *testing.T) {
	lines := []string{"a-1", "b-2", "a-3"}
	if got := filterLines(lines, "a-"); len(got) != 2 {
		t.Fatalf("子串过滤 = %v", got)
	}
	if got := filterLines(lines, `/^a/`); len(got) != 2 {
		t.Fatalf("正则过滤 = %v", got)
	}
	if got := filterLines(lines, ""); len(got) != 3 {
		t.Fatal("空 grep 原样返回")
	}
}
