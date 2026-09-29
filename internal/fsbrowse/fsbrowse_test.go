package fsbrowse

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func newManager(t *testing.T) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	return New([]string{dir}), dir
}

func TestResolveTraversalAndSymlink(t *testing.T) {
	m, dir := newManager(t)
	realDir, _ := filepath.EvalSymlinks(dir) // macOS 的 /var、/tmp 是软链

	if rp, err := m.resolve(dir); err != nil || rp != realDir {
		t.Fatalf("根目录应放行: %v %v", rp, err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := m.resolve(filepath.Join(dir, "sub")); err != nil {
		t.Fatalf("根目录内路径应放行: %v", err)
	}
	if _, err := m.resolve("/etc/passwd"); err == nil {
		t.Fatal("根目录外路径应拒绝")
	}
	if _, err := m.resolve(dir + "/../.."); err == nil {
		t.Fatal(".. 穿越应拒绝")
	}
	if _, err := m.resolve(filepath.Join(dir, "not-exist")); err == nil {
		t.Fatal("不存在的路径应拒绝")
	}

	// 软链逃逸：指向根目录外的文件必须被拒绝
	if runtime.GOOS != "windows" {
		outside := filepath.Join(t.TempDir(), "outside.txt")
		if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "evil")); err != nil {
			t.Skip("无法创建软链:", err)
		}
		if _, err := m.resolve(filepath.Join(dir, "evil")); err == nil {
			t.Fatal("软链逃逸应拒绝")
		}
	}
}

func TestListRootViewAndDir(t *testing.T) {
	m, dir := newManager(t)
	realDir, _ := filepath.EvalSymlinks(dir)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}

	// 空路径 = 根视图：每个根目录一项
	root, err := m.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(root.Entries) != 1 || !root.Entries[0].IsDir {
		t.Fatalf("根视图错误: %+v", root.Entries)
	}

	// 目录浏览：目录在前、路径为 realpath
	listing, err := m.List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if listing.Path != realDir {
		t.Fatalf("Path = %q, want %q", listing.Path, realDir)
	}
	if listing.Entries[0].Name != "sub" || !listing.Entries[0].IsDir {
		t.Fatalf("目录应排在最前: %+v", listing.Entries[0])
	}
	// 根目录本身的 parent 为空（回到根视图）
	if listing.Parent != "" {
		t.Fatalf("根目录的 Parent 应为空, got %q", listing.Parent)
	}
	// 非根目录的 parent 指向上级
	sub, _ := m.List(filepath.Join(dir, "sub"))
	if sub.Parent != realDir {
		t.Fatalf("Parent = %q, want %q", sub.Parent, realDir)
	}
}

func TestReadPreviewAndBinary(t *testing.T) {
	m, dir := newManager(t)
	if err := os.WriteFile(filepath.Join(dir, "t.txt"), []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin.dat"), []byte{'a', 0x00, 'b'}, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := m.Read(filepath.Join(dir, "t.txt"), true)
	if err != nil || res.Content != "one\ntwo\n" || res.Binary {
		t.Fatalf("文本预览错误: %+v err=%v", res, err)
	}

	res, err = m.Read(filepath.Join(dir, "bin.dat"), false)
	if err != nil || !res.Binary {
		t.Fatalf("二进制应识别: %+v err=%v", res, err)
	}

	// 截断：文件 > 256KB
	big := strings.Repeat("x", 300*1024)
	if err := os.WriteFile(filepath.Join(dir, "big.log"), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	head, _ := m.Read(filepath.Join(dir, "big.log"), false)
	if !head.Truncated || len(head.Content) != 256*1024 {
		t.Fatalf("head 截断错误: truncated=%v len=%d", head.Truncated, len(head.Content))
	}
	tail, _ := m.Read(filepath.Join(dir, "big.log"), true)
	if !tail.Truncated || !strings.HasSuffix(tail.Content, strings.Repeat("x", 10)) {
		t.Fatalf("tail 截断错误: truncated=%v", tail.Truncated)
	}

	if _, err := m.Read(filepath.Join(dir, "nope"), false); err == nil {
		t.Fatal("不存在的文件应报错")
	}
}

func TestDisabledWhenNoRoots(t *testing.T) {
	m := New(nil)
	if _, err := m.List(""); err == nil && len(m.resolvedRoots()) > 0 {
		t.Fatal("fs_roots 为空应关闭能力")
	}
	if _, err := m.resolve("/tmp"); err == nil {
		t.Fatal("fs_roots 为空应拒绝一切")
	}
}
