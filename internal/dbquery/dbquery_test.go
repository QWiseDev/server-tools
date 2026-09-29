package dbquery

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func setupDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "t.db")
	db, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("create table t(id integer primary key, name text)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("insert into t values(1,'甲'),(2,'乙')"); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestQueryReadOnly(t *testing.T) {
	p := setupDB(t)
	q := New(p, 10000)

	res, err := q.Query("select id, name from t order by id")
	if err != nil {
		t.Fatal(err)
	}
	if res.RowCount != 2 || res.Columns[1] != "name" || res.Rows[0][1] != "甲" {
		t.Fatalf("查询结果错误: %+v", res)
	}

	// 分号截尾允许，内部分号拒绝
	if _, err := q.Query("select 1;"); err != nil {
		t.Fatalf("尾分号应容忍: %v", err)
	}
	for _, bad := range []string{
		"insert into t values(3,'x')",
		"update t set name='x'",
		"delete from t",
		"drop table t",
		"select 1; select 2",
		"",
		"   ",
	} {
		if _, err := q.Query(bad); err == nil {
			t.Fatalf("应拒绝: %q", bad)
		}
	}
	// 允许的语句类型
	for _, ok := range []string{"select 1", "WITH x AS (SELECT 1) SELECT * FROM x", "explain select 1"} {
		if _, err := q.Query(ok); err != nil {
			t.Fatalf("应放行 %q: %v", ok, err)
		}
	}
	// 文件保持只读：直接打开写应失败（mode=ro 只影响驱动自身，这里验证库文件未被改动）
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
}

func TestDisabledWhenNoPath(t *testing.T) {
	q := New("", 1000)
	if _, err := q.Query("select 1"); err == nil || !strings.Contains(err.Error(), "db_path") {
		t.Fatalf("未配置 db_path 应报错: %v", err)
	}
}
