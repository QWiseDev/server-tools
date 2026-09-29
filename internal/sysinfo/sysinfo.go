// Package sysinfo 提供系统概况、进程列表与监听端口查询（基于 gopsutil）。
package sysinfo

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// Overview 是服务器概况。
type Overview struct {
	UptimeH     float64   `json:"uptime_h"`
	Load        []float64 `json:"load"`
	MemUsedPct  float64   `json:"mem_used_pct"`
	MemTotalGB  float64   `json:"mem_total_gb"`
	DiskUsedPct float64   `json:"disk_used_pct"`
	Top         []Proc    `json:"top"`
}

// Proc 是一行进程信息。
type Proc struct {
	PID     int32   `json:"pid"`
	Name    string  `json:"name"`
	User    string  `json:"user"`
	CPU     float64 `json:"cpu"`
	Mem     float64 `json:"mem"`
	Started string  `json:"started"`
}

func fmtTime(sec int64) string {
	if sec <= 0 {
		return "-"
	}
	return time.Unix(sec, 0).Format("01-02 15:04")
}

// collect 采集全部进程。gopsutil 首次 CPUPercent 返回的是进程启动以来的
// 生命周期均值，所以先空扫一遍建立基线，等 300ms 再正式采样，
// 得到的才是采样窗口内的实时 CPU（与 psutil 的 priming 语义一致）。
func collect() []Proc {
	procs, _ := process.Processes()
	for _, p := range procs {
		_, _ = p.CPUPercent()
	}
	time.Sleep(300 * time.Millisecond)
	out := make([]Proc, 0, len(procs))
	for _, p := range procs {
		name, _ := p.Name()
		user, _ := p.Username()
		cpuPct, _ := p.CPUPercent()
		memPct, _ := p.MemoryPercent()
		ct, _ := p.CreateTime()
		n := name
		if len(n) > 32 {
			n = n[:32]
		}
		out = append(out, Proc{
			PID:     p.Pid,
			Name:    n,
			User:    user,
			CPU:     round1(cpuPct),
			Mem:     round1(float64(memPct)),
			Started: fmtTime(ct / 1000),
		})
	}
	return out
}

// GetOverview 返回运行时长、负载、内存/磁盘与 CPU Top 进程。
func GetOverview() (*Overview, error) {
	vm, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}
	du, err := disk.Usage("/")
	if err != nil {
		return nil, err
	}
	la, err := load.Avg()
	if err != nil {
		return nil, err
	}
	boot, _ := host.BootTime()
	top := Processes("cpu", 6)
	return &Overview{
		UptimeH:     float64(time.Now().Unix()-int64(boot)) / 3600,
		Load:        []float64{round1(la.Load1), round1(la.Load5), round1(la.Load15)},
		MemUsedPct:  round1(vm.UsedPercent),
		MemTotalGB:  float64(vm.Total) / 1e9,
		DiskUsedPct: round1(du.UsedPercent),
		Top:         top,
	}, nil
}

// Processes 返回按 cpu 或 mem 排序的前 limit 个进程。
func Processes(sortBy string, limit int) []Proc {
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	rows := collect()
	if sortBy == "mem" {
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].Mem > rows[j].Mem })
	} else {
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].CPU > rows[j].CPU })
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// PortRow 是一行监听端口信息。
type PortRow struct {
	Port uint32 `json:"port"`
	PID  int32  `json:"pid"`
	Proc string `json:"proc"`
}

// ListeningPorts 返回当前 TCP 监听端口及归属进程。
func ListeningPorts() ([]PortRow, error) {
	conns, err := net.Connections("tcp")
	if err != nil {
		return nil, fmt.Errorf("读取网络连接失败: %w", err)
	}
	seen := map[uint32]PortRow{}
	for _, c := range conns {
		if c.Status != "LISTEN" {
			continue
		}
		port := c.Laddr.Port
		if port == 0 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		row := PortRow{Port: port, PID: -1, Proc: "-"}
		if c.Pid > 0 {
			row.PID = c.Pid
			if p, err := process.NewProcess(c.Pid); err == nil {
				if n, err := p.Name(); err == nil && n != "" {
					if len(n) > 32 {
						n = n[:32]
					}
					row.Proc = n
				}
			}
		}
		seen[port] = row
	}
	out := make([]PortRow, 0, len(seen))
	for _, r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out, nil
}

// JVMProc 是一行 JVM 进程信息（供 Arthas 选择 attach 目标）。
type JVMProc struct {
	PID      int32  `json:"pid"`
	Name     string `json:"name"`
	IsTomcat bool   `json:"is_tomcat"`
	Cmd      string `json:"cmd"`
}

// ListJVMs 返回疑似 JVM 的进程（名字含 java 或命令行含 catalina.home）。
func ListJVMs() []JVMProc {
	var out []JVMProc
	procs, _ := process.Processes()
	for _, p := range procs {
		name, _ := p.Name()
		cmdline, _ := p.Cmdline()
		isTomcat := strings.Contains(cmdline, "catalina.home")
		if !strings.HasPrefix(strings.ToLower(name), "java") && !isTomcat {
			continue
		}
		n := name
		if n == "" {
			n = "java"
		}
		if len(n) > 32 {
			n = n[:32]
		}
		cmd := cmdline
		if len(cmd) > 200 {
			cmd = cmd[:200]
		}
		out = append(out, JVMProc{PID: p.Pid, Name: n, IsTomcat: isTomcat, Cmd: cmd})
	}
	return out
}

func round1(f float64) float64 {
	v, _ := strconv.ParseFloat(fmt.Sprintf("%.1f", f), 64)
	return v
}
