package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/span-dev/span/internal/analyzer"
	"github.com/span-dev/span/internal/output"
	"github.com/span-dev/span/internal/parser"
	"github.com/span-dev/span/internal/scanner"
	"github.com/span-dev/span/pkg/models"
)

const (
	Version   = "0.1.0"
	BuildTime = "dev"
	Commit    = "dev"
)

const Banner = `
   _____  ____  __  ______  __
  / ___/ / __ \/  |/  /   \/_/
  \__ \ / /_/ / /|_/ / /| | / /
 ___/ // _, _/ /  / / ___ |/ /
/____//_/ |_/_/  /_/_/  |_/_/

  v%s  |  Internal Lateral Movement Analyzer
`

const Disclaimer = `
=======================================================================
  [!] DISCLAIMER / 免责声明
  本工具仅供授权的渗透测试和安全研究使用。
  未经目标系统所有者明确书面授权，使用本工具进行扫描或攻击
  属于违法行为，后果自负。
  The user assumes all legal responsibility.
=======================================================================
`

// Config 命令行配置
type Config struct {
	Target       string
	TargetFile   string
	OutputFile   string // -o 参数，输出文件路径
	Threads      int
	Timeout      int // 毫秒
	Analyze      string
	RulesFile    string
	Verbose      bool
	CriticalOnly bool
	NoICMP       bool
	PortList     string
}

func main() {
	// 子命令
	if len(os.Args) > 1 && (os.Args[1] == "-v" || os.Args[1] == "--version") {
		printVersion()
		return
	}

	var cfg Config

	// 位置参数：目标 IP/CIDR
	if len(os.Args) > 1 && !startsWith(os.Args[1], "-") {
		cfg.Target = os.Args[1]
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}

	// 命令行参数
	flag.StringVar(&cfg.TargetFile, "f", "", "目标文件，每行一个 IP/CIDR")
	flag.IntVar(&cfg.Threads, "threads", 10, "并发线程数（默认 10，隐蔽模式）")
	flag.IntVar(&cfg.Timeout, "timeout", 2000, "端口超时（毫秒）")
	flag.StringVar(&cfg.Analyze, "analyze", "", "分析模式：读取 fscan/nmap 输出文件")
	flag.StringVar(&cfg.RulesFile, "rules", "", "外部规则文件路径（覆盖内置规则）")
	flag.BoolVar(&cfg.Verbose, "v", false, "详细模式（含教学解释）")
	flag.BoolVar(&cfg.CriticalOnly, "critical-only", false, "仅显示 Critical 级别攻击面")
	flag.BoolVar(&cfg.NoICMP, "no-icmp", false, "禁用 ICMP 存活探测（仅 TCP）")
	flag.StringVar(&cfg.PortList, "ports", "", "自定义端口列表（逗号分隔）")
	flag.StringVar(&cfg.OutputFile, "o", "span_result.txt", "结果输出文件路径")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, Banner+"\n", Version)
		fmt.Fprintf(os.Stderr, "Usage: span [target] [options]\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  span 192.168.52.0/24              # 扫描整个网段\n")
		fmt.Fprintf(os.Stderr, "  span 192.168.52.138                 # 扫描单台主机\n")
		fmt.Fprintf(os.Stderr, "  span -f targets.txt                 # 从文件读取目标\n")
		fmt.Fprintf(os.Stderr, "  span 192.168.52.0/24 -threads 100   # 高速扫描\n")
		fmt.Fprintf(os.Stderr, "  span --analyze fscan.txt         # 分析 fscan 结果（支持 fscan/nmap 格式）\n")
		fmt.Fprintf(os.Stderr, "  span 192.168.52.0/24 -v             # 详细模式\n")
		fmt.Fprintf(os.Stderr, "  span 192.168.52.0/24 -critical-only # 仅显示关键攻击面\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// 打印 Banner
	fmt.Printf(Banner+"\n", Version)
	fmt.Print(Disclaimer)
	fmt.Printf("[*] Span %s starting at %s\n", Version, time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("[*] Runtime: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()

	// 检查参数
	if cfg.Target == "" && cfg.TargetFile == "" && cfg.Analyze == "" {
		fmt.Fprintln(os.Stderr, "[!] Error: 未指定目标")
		fmt.Fprintln(os.Stderr, "[!] 使用 span -h 查看帮助")
		os.Exit(1)
	}

	// 分析模式 vs 扫描模式
	if cfg.Analyze != "" {
		runAnalyze(&cfg)
	} else {
		// Phase 1: 执行扫描
		runScan(&cfg)
	}

	fmt.Println()
	fmt.Println("[*] 完成")
}

func printVersion() {
	fmt.Printf("span version %s\n", Version)
	fmt.Printf("  commit: %s\n", Commit)
	fmt.Printf("  build:  %s\n", BuildTime)
	fmt.Printf("  go:     %s\n", runtime.Version())
	fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

func startsWith(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}

// parsePorts 解析端口列表（逗号分隔）
func parsePorts(portStr string) ([]int, error) {
	parts := strings.Split(portStr, ",")
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		var port int
		_, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &port)
		if err != nil {
			return nil, fmt.Errorf("无效的端口: %s", p)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("端口超出范围: %d", port)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

// parseTargets 解析目标（CIDR 或文件）
func parseTargets(cfg *Config) ([]string, error) {
	var targets []string

	// 从文件读取
	if cfg.TargetFile != "" {
		data, err := os.ReadFile(cfg.TargetFile)
		if err != nil {
			return nil, fmt.Errorf("读取目标文件失败: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue // 跳过空行和注释
			}
			targets = append(targets, line)
		}
	} else if cfg.Target != "" {
		targets = append(targets, cfg.Target)
	} else {
		return nil, fmt.Errorf("未指定目标")
	}

	// 解析每个目标（CIDR -> IP 列表）
	var ips []string
	for _, t := range targets {
		if strings.Contains(t, "/") {
			// CIDR
			cidrIPs, err := models.CIDRToIPs(t)
			if err != nil {
				return nil, fmt.Errorf("解析 CIDR 失败: %s, %v", t, err)
			}
			ips = append(ips, cidrIPs...)
		} else {
			// 单个 IP
			ips = append(ips, t)
		}
	}

	return ips, nil
}

// runScan 执行扫描流程
func runScan(cfg *Config) {
	// 1. 解析目标
	ips, err := parseTargets(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[*] 解析目标: %d 个 IP\n", len(ips))

	// 2. 解析端口列表
	ports := scanner.DefaultPorts()
	if cfg.PortList != "" {
		ports, err = parsePorts(cfg.PortList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] 自定义端口: %v\n", ports)
	}

	// 3. 存活探测
	timeout := time.Duration(cfg.Timeout) * time.Millisecond
	fmt.Printf("[*] 开始存活探测...\n")
	aliveIPs := scanner.CheckAlives(ips, timeout, cfg.Threads)
	fmt.Printf("[+] 发现存活主机: %d 台\n", len(aliveIPs))

	if len(aliveIPs) == 0 {
		fmt.Println("[-] 未发现存活主机")
		return
	}

	// 4. 端口扫描
	fmt.Printf("[*] 开始端口扫描（%d 个端口）...\n", len(ports))
	hosts := scanner.ScanHosts(aliveIPs, ports, timeout, cfg.Threads)

	// 5. Phase 2: OS 判断 + 角色推断
	fmt.Printf("[*] 开始 OS 判断和角色推断...\n")
	for i := range hosts {
		h := &hosts[i]
		if !h.IsAlive {
			continue
		}

		openPorts := h.GetOpenPorts()

		// 构建 Banner 映射（用于 OS 判断）
		bannerMap := make(map[int]string)
		for _, p := range openPorts {
			if p.Banner != "" {
				bannerMap[p.Port] = p.Banner
			}
		}

		// OS 启发式判断
		h.OS = analyzer.AnalyzeOS(h.TTL, openPorts, bannerMap)

		// 角色推断（基于端口组合）
		h.Roles = analyzer.AnalyzeRole(openPorts)
	}
	fmt.Println("[+] 分析完成")

	// 6. Phase 3: 攻击面分析 + 命令生成
	fmt.Printf("[*] 开始攻击面分析...\n")
	for i := range hosts {
		h := &hosts[i]
		if !h.IsAlive {
			continue
		}
		h.Suggestions = analyzer.AnalyzeAttacks(h)
	}
	fmt.Println("[+] 攻击面分析完成")

	// 7. 构造结果
	result := &models.ScanResult{
		Targets:    cfg.Target,
		Hosts:      hosts,
		AliveCount: len(aliveIPs),
		TotalPorts: 0,
	}
	for _, h := range hosts {
		result.TotalPorts += len(h.GetOpenPorts())
	}

	// 8. 终端输出
	output.PrintResult(result, cfg.Verbose, cfg.CriticalOnly)

	// 9. 文件输出
	err = output.WriteFile(result, cfg.OutputFile, cfg.Verbose, cfg.CriticalOnly)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] 写入文件失败: %v\n", err)
	}
}

// runAnalyze 执行分析模式（Phase 4）：解析 fscan/nmap 输出文件
func runAnalyze(cfg *Config) {
	fmt.Printf("[*] 分析模式: 读取 %s\n", cfg.Analyze)

	// 1. 调用解析器
	result, err := parser.ParseFile(cfg.Analyze)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] 解析失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] 解析完成: %d 台主机 (存活 %d, 开放端口 %d)\n",
		len(result.Hosts), result.AliveCount, result.TotalPorts)

	// 2. 构造 ScanResult 用于输出
	scanResult := &models.ScanResult{
		Targets:    cfg.Analyze,
		Hosts:      result.Hosts,
		AliveCount: result.AliveCount,
		TotalPorts: result.TotalPorts,
	}

	// 3. 终端输出
	output.PrintResult(scanResult, cfg.Verbose, cfg.CriticalOnly)

	// 4. 文件输出
	err = output.WriteFile(scanResult, cfg.OutputFile, cfg.Verbose, cfg.CriticalOnly)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] 写入文件失败: %v\n", err)
	}

	fmt.Println()
	fmt.Printf("[*] 分析完成，结果已保存至 %s\n", cfg.OutputFile)
}
