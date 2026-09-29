// Package arthas 提供 JVM 发现、Arthas agent attach 与只读命令执行（telnet）。
package arthas

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// telnetMini 处理 telnet 协商（IAC），应答协商并剥掉控制字节只留正文。
// Arthas(netty telnet) 在协商完成前不会输出任何数据，因此这一步不能省。
type telnetMini struct{ pending []byte }

func (t *telnetMini) feed(data []byte) (reply, plain []byte) {
	data = append(t.pending, data...)
	t.pending = nil
	var rep, pl []byte
	i, n := 0, len(data)
loop:
	for i < n {
		b := data[i]
		if b != 0xFF {
			pl = append(pl, b)
			i++
			continue
		}
		if i+1 >= n { // 半个 IAC，留到下一段
			t.pending = append([]byte(nil), data[i:]...)
			break
		}
		cmd := data[i+1]
		switch {
		case (cmd == 0xFB || cmd == 0xFC || cmd == 0xFD || cmd == 0xFE) && i+2 < n:
			opt := data[i+2]
			switch cmd {
			case 0xFB: // 对端 WILL -> 我们 DO
				rep = append(rep, 0xFF, 0xFD, opt)
			case 0xFD: // 对端 DO -> 我们 WILL
				rep = append(rep, 0xFF, 0xFB, opt)
				if opt == 0x1F { // NAWS：上报窗口大小 200x50
					rep = append(rep, 0xFF, 0xFA, 0x1F, 0x00, 0xC8, 0x00, 0x32, 0xFF, 0xF0)
				}
			}
			i += 3
		case cmd == 0xFA: // SB ... IAC SE 子协商
			j := indexIACSE(data[i:])
			if j == -1 {
				t.pending = append([]byte(nil), data[i:]...)
				break loop
			}
			sub := data[i+2 : i+j]
			if len(sub) > 0 && sub[0] == 0x18 { // TTYPE SEND -> 回 IS xterm
				rep = append(rep, 0xFF, 0xFA, 0x18, 0x00, 'x', 't', 'e', 'r', 'm', 0xFF, 0xF0)
			}
			i = i + j + 2
		case cmd == 0xFF: // 转义的 0xff 数据
			pl = append(pl, 0xFF)
			i += 2
		default: // NOP 等两字节命令
			i += 2
		}
	}
	return rep, pl
}

// indexIACSE 在 b 中查找 "IAC SE"（FF F0）。
func indexIACSE(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == 0xFF && b[i+1] == 0xF0 {
			return i
		}
	}
	return -1
}

// telnetCommand 连接 addr 执行一条命令，返回剥掉协议字节的输出。
// 完成判定与 Python 版一致：发送后看到「回显提示符 + 结束提示符」两处 ]$；
// 流式命令（watch/trace）靠 idle>=3 秒兜底收尾。
func telnetCommand(addr, command string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", fmt.Errorf("连接 %s 失败: %w", addr, err)
	}
	defer conn.Close()

	tn := &telnetMini{}
	var raw []byte
	sent, sentAt := false, 0
	idle := 0
	start := time.Now()
	deadline := start.Add(timeout)
	buf := make([]byte, 65536)

	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, rerr := conn.Read(buf)
		if n > 0 {
			rep, pl := tn.feed(buf[:n])
			if len(rep) > 0 {
				if _, err := conn.Write(rep); err != nil {
					break
				}
			}
			raw = append(raw, pl...)
			idle = 0
			// 协商完成、见到 banner 后再发命令；3 秒仍无输出则兜底直发
			if !sent && (len(pl) > 0 || time.Since(start) > 3*time.Second) {
				_, _ = conn.Write([]byte(command + "\n"))
				sent, sentAt = true, len(raw)
			}
			if sent {
				tail := ansiClean(string(raw[sentAt:]))
				if strings.Count(tail, "]$") >= 2 &&
					strings.HasSuffix(strings.TrimRight(tail, " \t\r\n"), "]$") {
					break
				}
			}
		}
		if rerr != nil { // 读超时或 EOF
			if n == 0 && errors.Is(rerr, io.EOF) {
				break
			}
			idle++
			if !sent && idle >= 2 {
				_, _ = conn.Write([]byte(command + "\n"))
				sent, sentAt = true, len(raw)
			}
			if sent && len(raw) > sentAt && idle >= 3 {
				break // 3 秒无新输出视为完成
			}
		}
	}
	return postProcess(string(raw), command), nil
}

// ansiClean 剥掉 ANSI 转义序列（颜色/光标控制等）。
func ansiClean(s string) string { return ansiRe.ReplaceAllString(s, "") }

// postProcess 去掉 banner 与回显，只留命令结果。
func postProcess(raw, command string) string {
	text := strings.TrimSpace(ansiClean(raw))
	parts := strings.Split(text, "]$")
	out := text
	if len(parts) >= 2 {
		out = parts[len(parts)-2]
	}
	out = strings.TrimSpace(out)
	out = strings.TrimPrefix(out, command)
	out = strings.TrimSpace(out)
	out = trailingPrompt.ReplaceAllString(out, "")
	return strings.TrimSpace(out)
}
