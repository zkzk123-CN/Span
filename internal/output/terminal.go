package output

import (
	"fmt"
	"strings"

	"github.com/span-dev/span/internal/analyzer"
	"github.com/span-dev/span/pkg/models"
)

// ANSI 颜色码（中国区约定：警告/上涨=红色，安全/下跌=绿色）
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m" // Critical / 警告 / 上涨
	ColorGreen  = "\033[32m" // Low / 安全 / 下跌
	ColorYellow = "\033[33m" // High
	ColorBlue   = "\033[34m" // Medium
	ColorCyan   = "\033[36m" // 信息
	ColorBold   = "\033[1m"
)

// PrintResult 将扫描结果输出到终端（带颜色）
func PrintResult(result *models.ScanResult, verbose bool, criticalOnly bool) {
	// 扫描头
	printHeader(result.Targets)

	// 存活主机统计
	fmt.Printf("\n[+] 发现存活主机: %d 台\n", result.AliveCount)
	if result.AliveCount == 0 {
		fmt.Println("[*] 未发现存活主机")
		return
	}

	// 每台主机的详细信息
	for _, host := range result.Hosts {
		if !host.IsAlive {
			continue
		}
		printHostTerminal(&host, verbose, criticalOnly)
	}

	// 底部免责声明
	printFooter()
}

// printHeader 打印扫描头
func printHeader(target string) {
	line := "=========================================================================="
	fmt.Println()
	fmt.Printf("[*] Span v0.1.0 - 内网横向移动分析\n")
	fmt.Printf("[*] 扫描目标: %s\n", target)
	fmt.Printf("[*] 免责声明: 本工具仅供授权渗透测试使用，非法使用后果自负\n")
	fmt.Println(line)
}

// printFooter 打印底部免责声明
func printFooter() {
	fmt.Println()
	fmt.Println("[!] 以下建议仅供授权测试参考，请确保已获得合法授权！")
	fmt.Println("==========================================================================")
}

// printHostTerminal 在终端打印单台主机的详细信息（带颜色）
func printHostTerminal(host *models.Host, verbose bool, criticalOnly bool) {
	fmt.Printf("\n[+] %s", host.String())
	if host.TTL > 0 {
		fmt.Printf(" (TTL=%d)", host.TTL)
	}
	fmt.Println()

	// ===== 端口列表 =====
	openPorts := host.GetOpenPorts()
	if len(openPorts) == 0 {
		fmt.Println("    [-] 无开放端口（可能仅开放 Web 端口 80/443，未在本工具扫描范围内）")
		fmt.Println("    [提示] 如需扫描 Web 端口，请使用 nmap 或 fscan 进行全端口扫描")
		return
	}

	// ===== OS 判断区域 =====
	if host.OS.Guess != "" && host.OS.Guess != "未知" {
		confColor := ColorYellow
		if host.OS.Confidence == "high" {
			confColor = ColorGreen
		} else if host.OS.Confidence == "low" {
			confColor = ColorRed
		}
		fmt.Printf("    %s[OS]  %s%s (置信度: %s | 方法: %s)%s\n",
			ColorCyan, host.OS.Guess, confColor,
			host.OS.Confidence, host.OS.Method, ColorReset)
	}

	// ===== 角色推断区域 =====
	if len(host.Roles) > 0 && host.Roles[0].Role != "" {
		// 显示前3个角色候选（按置信度排序）
		for i, role := range host.Roles {
			if i >= 3 {
				break
			}

			roleColor := ColorBold + ColorYellow
			if role.Confidence >= 0.8 {
				roleColor = ColorBold + ColorRed
			} else if role.Confidence < 0.5 {
				roleColor = ColorBlue
			}

			if i == 0 {
				// 第一名角色（主角色）
				fmt.Printf("    %s[角色] %s%s (置信度: %.0f%%)%s\n",
					ColorCyan, roleColor, role.Role, role.Confidence*100, ColorReset)
				if verbose || role.Desc != "" {
					fmt.Printf("          └─ %s\n", role.Desc)
				}

				// 显示匹配的端口（辅助验证）
				if verbose && len(role.MatchedPorts) > 0 {
					portsStr := formatIntSlice(role.MatchedPorts)
					fmt.Printf("          └─ 匹配端口: [%s]\n", portsStr)
				}
			} else {
				// 候选角色（次要）
				fmt.Printf("    %s[候选] %s%s (置信度: %.0f%%)%s\n",
					ColorCyan, roleColor, role.Role, role.Confidence*100, ColorReset)
				if verbose && role.Desc != "" {
					fmt.Printf("          └─ %s\n", role.Desc)
				}
			}
		}
	}

	// 分隔线
	if host.OS.Guess != "" || len(host.Roles) > 0 {
		fmt.Println("    " + strings.Repeat("-", 50))
	}

	// 表头
	fmt.Printf("    %-8s %-12s %-10s %s\n", "端口", "服务", "风险", "说明")
	fmt.Printf("    %-8s %-12s %-10s %s\n", "----", "----", "----", "----")

	// 端口列表
	for _, p := range openPorts {
		// 如果 criticalOnly=true，跳过非 Critical 端口
		if criticalOnly && p.Risk != models.RiskCritical {
			continue
		}

		riskStr := colorizeRisk(string(p.Risk))
		desc := getPortDescFromRules(p.Port)

		fmt.Printf("    %-8d %-12s %-10s %s\n", p.Port, p.Service, riskStr, desc)

		// 如果 verbose=true，打印 Banner
		if verbose && p.Banner != "" {
			fmt.Printf("    > Banner: %s\n", p.Banner)
		}
	}

	// ===== 攻击建议区域 =====
	if len(host.Suggestions) > 0 {
		fmt.Print(analyzer.FormatSuggestions(host.Suggestions, verbose))
	}
}

// colorizeRisk 为风险等级添加颜色
func colorizeRisk(risk string) string {
	switch models.RiskLevel(risk) {
	case models.RiskCritical:
		return ColorRed + "[Critical]" + ColorReset
	case models.RiskHigh:
		return ColorYellow + "[High]    " + ColorReset
	case models.RiskMedium:
		return ColorBlue + "[Medium]  " + ColorReset
	case models.RiskLow:
		return ColorGreen + "[Low]     " + ColorReset
	default:
		return "[Unknown] "
	}
}
