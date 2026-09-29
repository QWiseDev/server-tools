package logsw

// 全文件搜索：面向大日志文件（GB 级）的流式 grep。
// 按行流式扫描、只保留命中行；单页命中达到 limit 即停并给出 next_offset，
// 客户端带 offset 续扫即可翻页，内存占用恒定。

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// SearchMatch 是一条命中记录。
type SearchMatch struct {
	Line int    `json:"line"` // 1-based 全文件行号
	Text string `json:"text"`
}

// SearchResult 是一次搜索（一页）的结果。
type SearchResult struct {
	Source       string        `json:"source"`
	Pattern      string        `json:"pattern"`
	Matches      []SearchMatch `json:"matches"`
	Complete     bool          `json:"complete"`      // 是否已扫到文件尾
	ScannedBytes int64         `json:"scanned_bytes"` // 本次扫描覆盖的字节数（不含行号补算）
	NextOffset   int64         `json:"next_offset"`   // Complete=false 时的续扫起点
	FileSize     int64         `json:"file_size"`
}

// matcher 统一子串与 /正则/ 两种模式。
type matcher func(line []byte) bool

// buildMatcher 与 tail 过滤保持同一语义：/.../ 按正则，否则按子串；ci 忽略大小写。
func buildMatcher(grep string, ci bool) (matcher, error) {
	if grep == "" {
		return nil, fmt.Errorf("搜索模式为空")
	}
	if len(grep) > 2 && strings.HasPrefix(grep, "/") && strings.HasSuffix(grep, "/") {
		expr := grep[1 : len(grep)-1]
		if ci {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("正则无效: %v", err)
		}
		return re.Match, nil
	}
	if ci {
		needle := []byte(strings.ToLower(grep))
		return func(line []byte) bool {
			return bytes.Contains(bytes.ToLower(line), needle)
		}, nil
	}
	needle := []byte(grep)
	return func(line []byte) bool {
		return bytes.Contains(line, needle)
	}, nil
}

// countNewlinesBefore 快速统计 offset 之前的换行数，用于续扫时还原全文件行号。
func countNewlinesBefore(f *os.File, offset int64) (int, error) {
	if offset <= 0 {
		return 0, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	buf := make([]byte, 1<<20)
	total := 0
	var read int64
	for read < offset {
		n := int64(len(buf))
		if offset-read < n {
			n = offset - read
		}
		got, err := io.ReadFull(f, buf[:n])
		total += bytes.Count(buf[:got], []byte{'\n'})
		read += int64(got)
		if err != nil {
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				break
			}
			return 0, err
		}
	}
	return total, nil
}

// Search 在白名单文件内做全量流式搜索。
// limit: 单页最多命中条数（1..1000，默认 200）；offset: 上页 next_offset；ci: 忽略大小写。
func (m *Manager) Search(source, grep string, limit int, offset int64, ci bool) (*SearchResult, error) {
	if strings.HasPrefix(source, "docker:") {
		return nil, fmt.Errorf("全文件搜索仅支持白名单文件（容器日志请用 tail 或先落盘）")
	}
	rp, err := m.allowed(source)
	if err != nil {
		return nil, err
	}
	match, err := buildMatcher(grep, ci)
	if err != nil {
		return nil, err
	}
	if limit < 1 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	f, err := os.Open(rp)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	out := &SearchResult{
		Source:   source,
		Pattern:  grep,
		FileSize: st.Size(),
		Matches:  []SearchMatch{},
	}
	if offset > st.Size() {
		out.Complete = true
		return out, nil
	}

	// 续扫时补算前面的换行数，行号才能与整文件对齐
	lineNo, err := countNewlinesBefore(f, offset)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}

	reader := bufio.NewReaderSize(f, 1<<20)
	var lastLineEnd int64 = offset
	for {
		line, rerr := reader.ReadBytes('\n')
		lastLineEnd += int64(len(line))
		if len(line) > 0 {
			lineNo++
			if match(line) {
				text := string(bytes.TrimRight(line, "\r\n"))
				out.Matches = append(out.Matches, SearchMatch{Line: lineNo, Text: text})
				if len(out.Matches) >= limit {
					out.NextOffset = lastLineEnd
					out.ScannedBytes = lastLineEnd - offset
					return out, nil
				}
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				out.Complete = true
				out.ScannedBytes = st.Size() - offset
				return out, nil
			}
			return nil, rerr
		}
	}
}
