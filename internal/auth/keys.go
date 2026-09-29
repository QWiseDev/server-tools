package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("auth: 无法获取随机数: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Key 是一个 MCP 接入密钥：Bearer 认证用 Key 值，Tools 决定该密钥可调用哪些工具。
type Key struct {
	Key      string   `json:"key"`
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Tools    []string `json:"tools"`
	Enabled  bool     `json:"enabled"`
	Created  string   `json:"created"`
	LastUsed string   `json:"last_used"`
}

// Allows 报告该密钥是否可调用指定工具。
func (k *Key) Allows(tool string) bool {
	if !k.Enabled {
		return false
	}
	for _, t := range k.Tools {
		if t == tool {
			return true
		}
	}
	return false
}

// KeyStore 是持久化在 keys.json 里的密钥表（0600 权限，原子写）。
type KeyStore struct {
	mu    sync.Mutex
	path  string
	valid map[string]bool // 允许授予的工具名集合
	byKey map[string]*Key
	byID  map[string]*Key
}

func NewKeyStore(path string, validTools []string) *KeyStore {
	valid := map[string]bool{}
	for _, t := range validTools {
		valid[t] = true
	}
	return &KeyStore{
		path:  path,
		valid: valid,
		byKey: map[string]*Key{},
		byID:  map[string]*Key{},
	}
}

// EnsureLoad 读取密钥文件；文件缺失或为空时生成一个全权限的 default 密钥并打印到日志。
func (s *KeyStore) EnsureLoad() error {
	data, err := os.ReadFile(s.path)
	if err == nil && len(data) > 0 {
		var keys []*Key
		if err := json.Unmarshal(data, &keys); err != nil {
			return fmt.Errorf("解析密钥文件 %s: %w", s.path, err)
		}
		for _, k := range keys {
			if k.Key == "" || k.ID == "" {
				continue
			}
			k.Tools = s.filterValid(k.Tools)
			s.byKey[k.Key] = k
			s.byID[k.ID] = k
		}
	}
	if len(s.byKey) == 0 {
		k := s.newKey("default", validAll(s.valid))
		if err := s.saveLocked(); err != nil {
			return err
		}
		fmt.Printf("[server-mcp] 已生成初始 MCP 密钥（全权限，可在控制台「密钥」页管理）：\n  %s\n", k.Key)
	}
	return nil
}

// List 返回全部密钥（内部指针的浅拷贝列表）。
func (s *KeyStore) List() []*Key {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Key, 0, len(s.byKey))
	for _, k := range s.byID {
		out = append(out, k)
	}
	return out
}

// GetByKey 按 Bearer 值取密钥；要求处于启用状态。
func (s *KeyStore) GetByKey(key string) *Key {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.byKey[key]
	if k == nil || !k.Enabled {
		return nil
	}
	return k
}

// Create 新建密钥，返回完整记录（含明文 key，仅创建时可见）。
func (s *KeyStore) Create(name string, tools []string) (*Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := s.filterValid(tools)
	if len(ts) == 0 {
		return nil, fmt.Errorf("至少为密钥勾选一个工具")
	}
	if name == "" {
		name = "未命名"
	}
	k := s.newKey(name, ts)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return k, nil
}

// Update 按 ID 修改名称/工具集/启用状态；tools 传 nil 表示不改。
func (s *KeyStore) Update(id, name string, tools []string, enabled *bool) (*Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.byID[id]
	if k == nil {
		return nil, fmt.Errorf("密钥不存在: %s", id)
	}
	if name != "" {
		k.Name = name
	}
	if tools != nil {
		ts := s.filterValid(tools)
		if len(ts) == 0 {
			return nil, fmt.Errorf("至少为密钥勾选一个工具")
		}
		k.Tools = ts
	}
	if enabled != nil {
		k.Enabled = *enabled
	}
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return k, nil
}

func (s *KeyStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.byID[id]
	if k == nil {
		return fmt.Errorf("密钥不存在: %s", id)
	}
	delete(s.byID, id)
	delete(s.byKey, k.Key)
	return s.saveLocked()
}

// Touch 更新最近使用时间（分钟粒度，避免频繁落盘）。
func (s *KeyStore) Touch(k *Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Format("2006-01-02 15:04")
	if k.LastUsed != now {
		k.LastUsed = now
		_ = s.saveLocked()
	}
}

// ---- 内部 ----

func (s *KeyStore) newKey(name string, tools []string) *Key {
	k := &Key{
		Key:     "sk-" + randomToken(),
		ID:      randomToken()[:10],
		Name:    name,
		Tools:   tools,
		Enabled: true,
		Created: time.Now().Format("2006-01-02 15:04"),
	}
	s.byKey[k.Key] = k
	s.byID[k.ID] = k
	return k
}

func (s *KeyStore) filterValid(tools []string) []string {
	var out []string
	for _, t := range tools {
		if s.valid[t] {
			out = append(out, t)
		}
	}
	return out
}

func (s *KeyStore) saveLocked() error {
	keys := make([]*Key, 0, len(s.byID))
	for _, k := range s.byID {
		keys = append(keys, k)
	}
	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func validAll(valid map[string]bool) []string {
	out := make([]string, 0, len(valid))
	for t := range valid {
		out = append(out, t)
	}
	return out
}
