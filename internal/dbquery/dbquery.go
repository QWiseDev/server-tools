// Package dbquery 提供只读的 SQLite 查询：仅允许单条 SELECT/WITH/EXPLAIN。
package dbquery

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动，免 CGO
)

// Querier 持有只读连接参数。dbPath 为空时查询能力关闭。
type Querier struct {
	dbPath    string
	maxOutput int
}

func New(dbPath string, maxOutput int) *Querier {
	return &Querier{dbPath: dbPath, maxOutput: maxOutput}
}

// QueryResult 是查询结果。
type QueryResult struct {
	Columns  []string `json:"columns"`
	Rows     [][]any  `json:"rows"`
	RowCount int      `json:"row_count"`
}

// Query 校验并执行单条只读 SQL，最多返回 500 行。
func (q *Querier) Query(sqlText string) (*QueryResult, error) {
	if q.dbPath == "" {
		return nil, fmt.Errorf("未配置 db_path，数据库查询能力已关闭（config.json）")
	}
	s := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(sqlText), ";"))
	if s == "" {
		return nil, fmt.Errorf("SQL 为空")
	}
	if strings.Contains(s, ";") {
		return nil, fmt.Errorf("一次只允许一条语句")
	}
	head := s
	if i := strings.IndexAny(s, " \t\r\n("); i >= 0 {
		head = s[:i]
	}
	switch strings.ToLower(head) {
	case "select", "with", "explain":
	default:
		return nil, fmt.Errorf("仅允许 SELECT / WITH / EXPLAIN（只读）")
	}

	dsn := "file:" + url.PathEscape(q.dbPath) +
		"?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	rows, err := db.Query(s)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := &QueryResult{Columns: cols}
	for rows.Next() && len(out.Rows) < 500 {
		raw := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		out.Rows = append(out.Rows, sanitize(raw))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out.RowCount = len(out.Rows)
	return out, nil
}

// sanitize 限制单元格体积：bytes 转 UTF-8 截断 120 字节，其余原样。
func sanitize(row []any) []any {
	out := make([]any, len(row))
	for i, v := range row {
		if b, ok := v.([]byte); ok {
			s := string(b)
			if len(s) > 120 {
				s = s[:120]
			}
			out[i] = s
			continue
		}
		out[i] = v
	}
	return out
}
