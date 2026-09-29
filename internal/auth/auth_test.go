package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionsVerifyAndExpiry(t *testing.T) {
	s := NewSessions(50 * time.Millisecond)

	if got := s.Verify("pw", "wrong"); got != "" {
		t.Fatalf("错误密码不应发 token: %q", got)
	}
	if got := s.Verify("", "pw"); got != "" {
		t.Fatal("未设置密码时不应发 token")
	}
	tok := s.Verify("pw", "pw")
	if tok == "" || !s.Check(tok) {
		t.Fatal("正确密码应发 token 且可校验")
	}
	time.Sleep(60 * time.Millisecond)
	if s.Check(tok) {
		t.Fatal("过期会话应失效")
	}
	tok2 := s.Verify("pw", "pw")
	s.Delete(tok2)
	if s.Check(tok2) {
		t.Fatal("删除后会话应失效")
	}
}

func TestKeyStoreLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	valid := []string{"tool_exec", "tool_overview"}

	s := NewKeyStore(path, valid)
	if err := s.EnsureLoad(); err != nil {
		t.Fatal(err)
	}
	def := s.List()
	if len(def) != 1 || def[0].Name != "default" || len(def[0].Tools) != 2 {
		t.Fatalf("首启应生成全权限 default: %+v", def)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("keys.json 应为 0600: %v", err)
	}
	if s.GetByKey(def[0].Key) == nil {
		t.Fatal("default key 应可用")
	}

	// 创建：非法工具被过滤；全非法应报错
	k, err := s.Create("a", []string{"tool_exec", "bogus"})
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Tools) != 1 || k.Tools[0] != "tool_exec" {
		t.Fatalf("非法工具应被过滤: %+v", k.Tools)
	}
	if !k.Allows("tool_exec") {
		t.Fatal("启用状态下 Allows 应为 true")
	}
	if k.Allows("tool_overview") {
		t.Fatal("未授权工具 Allows 应为 false")
	}
	if _, err := s.Create("b", []string{"bogus"}); err == nil {
		t.Fatal("无有效工具应报错")
	}

	// 停用后 GetByKey 返回 nil
	disabled := false
	if _, err := s.Update(k.ID, "", nil, &disabled); err != nil {
		t.Fatal(err)
	}
	if s.GetByKey(k.Key) != nil {
		t.Fatal("停用后应不可用")
	}
	if _, err := s.Update("no-such-id", "", nil, nil); err == nil {
		t.Fatal("更新不存在的密钥应报错")
	}

	// 删除
	if err := s.Delete(k.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(k.ID); err == nil {
		t.Fatal("重复删除应报错")
	}

	// 持久化：新实例读回 default
	s2 := NewKeyStore(path, valid)
	if err := s2.EnsureLoad(); err != nil {
		t.Fatal(err)
	}
	if len(s2.List()) != 1 || s2.List()[0].Name != "default" {
		t.Fatalf("重启后应保留 default: %+v", s2.List())
	}
}
