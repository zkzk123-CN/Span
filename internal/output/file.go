package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/span-dev/span/pkg/models"
)

// WriteFile 将扫描结果写入文件（纯文本，无颜色码）
// 默认文件路径：当前目录下的 span_result.txt
// 如果指定了 outputPath，则写入指定路径
func WriteFile(result *models.ScanResult, outputPath string, verbose bool, criticalOnly bool) error {
	if outputPath == "" {
		outputPath = "span_result.txt"
	}

	var sb strings.Builder

	// 扫描头
	sb.WriteString(fmt.Sprintf("Span v%s - 内网横向移动分析\n", "0.1.0"))
	sb.WriteString(fmt.Sprintf("扫描目标: %s\n", result.Targets))
	sb.WriteString(fmt.Sprintf("扫描时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("==========================================================================\n")
	sb.WriteString("免责声明: 本工具仅供授权渗透测试使用，非法使用后果自负\n")
	sb.WriteString("==========================================================================\n\n")

	// 存活主机统计
	sb.WriteString(fmt.Sprintf("[+] 发现存活主机: %d 台\n", result.AliveCount))
	if result.AliveCount == 0 {
		sb.WriteString("[-] 未发现存活主机\n")
	} else {
		// 每台主机的详细信息
		for i := range result.Hosts {
			host := &result.Hosts[i]
			if !host.IsAlive {
				continue
			}
			formatHostFile(&sb, host, verbose, criticalOnly)
		}
	}

	// 底部免责声明
	sb.WriteString("\n[!] 以下结果仅供授权测试参考，请确保已获得合法授权！\n")
	sb.WriteString("==========================================================================\n")

	// 写入文件
	err := os.WriteFile(outputPath, []byte(sb.String()), 0644)
	if err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	fmt.Printf("[*] 结果已保存到: %s\n", outputPath)
	return nil
}

// formatHostFile 格式化单台主机的信息（纯文本，无颜色）
func formatHostFile(sb *strings.Builder, host *models.Host, verbose bool, criticalOnly bool) {
	sb.WriteString(fmt.Sprintf("\n[+] %s", host.String()))
	if host.TTL > 0 {
		sb.WriteString(fmt.Sprintf(" (TTL=%d)", host.TTL))
	}
	sb.WriteString("\n")

	openPorts := host.GetOpenPorts()
	if len(openPorts) == 0 {
		sb.WriteString("    [-] 无开放端口\n")
		return
	}

	// ===== OS 判断区域 =====
	if host.OS.Guess != "" && host.OS.Guess != "未知" {
		sb.WriteString(fmt.Sprintf("    [OS]   %s (置信度: %s | 方法: %s)\n",
			host.OS.Guess, host.OS.Confidence, host.OS.Method))
	}

	// ===== 角色推断区域 =====
	if len(host.Roles) > 0 && (host.Roles[0].Role != "" || len(host.Roles) > 1) {
		bestRole := host.Roles[0]
		sb.WriteString(fmt.Sprintf("    [角色] %s (置信度: %.0f%%)\n",
			bestRole.Role, bestRole.Confidence*100))
		if bestRole.Desc != "" {
			sb.WriteString(fmt.Sprintf("           └─ %s\n", bestRole.Desc))
		}
		if verbose && len(bestRole.MatchedPorts) > 0 {
			portsStr := formatIntSlice(bestRole.MatchedPorts)
			sb.WriteString(fmt.Sprintf("           └─ 匹配端口: [%s]\n", portsStr))
		}
		if len(host.Roles) > 1 && verbose {
			for i := 1; i < len(host.Roles); i++ {
				r := host.Roles[i]
				sb.WriteString(fmt.Sprintf("    [候选] %s (%.0f%%): %s\n",
					r.Role, r.Confidence*100, r.Desc))
			}
		}
	}

	// 分隔线
	if host.OS.Guess != "" || len(host.Roles) > 0 {
		sb.WriteString("    " + strings.Repeat("-", 50) + "\n")
	}

	// 表头
	sb.WriteString(fmt.Sprintf("    %-8s %-12s %-10s %s\n", "端口", "服务", "风险", "说明"))
	sb.WriteString(fmt.Sprintf("    %-8s %-12s %-10s %s\n", "----", "----", "----", "----"))

	// 端口列表
	for _, p := range openPorts {
		if criticalOnly && p.Risk != models.RiskCritical {
			continue
		}

		riskStr := fmt.Sprintf("[%s]", p.Risk)
		desc := getPortDescFromRules(p.Port)

		sb.WriteString(fmt.Sprintf("    %-8d %-12s %-10s %s\n", p.Port, p.Service, riskStr, desc))

		// 如果 verbose=true，打印 Banner
		if verbose && p.Banner != "" {
			sb.WriteString(fmt.Sprintf("    > Banner: %s\n", p.Banner))
		}
	}

	// ===== 攻击建议区域（纯文本，无颜色码）=====
	if len(host.Suggestions) > 0 {
		sb.WriteString(fmt.Sprintf("\n    [攻击面] 发现 %d 个攻击建议（按优先级排序）:\n\n", len(host.Suggestions)))
		for i, s := range host.Suggestions {
			if i >= 5 && !verbose {
				sb.WriteString(fmt.Sprintf("    ... 还有 %d 个建议（使用 -v 查看全部）\n", len(host.Suggestions)-5))
				break
			}

			priorityIcon := ""
			switch s.Priority {
			case 1:
				priorityIcon = "[!]"
			case 2:
				priorityIcon = "[*]"
			default:
				priorityIcon = "[ ]"
			}

			sb.WriteString(fmt.Sprintf("    %s 优先级 %d | %s (%s)\n", priorityIcon, s.Priority, s.Service, s.Tool))
			sb.WriteString(fmt.Sprintf("       命令: %s\n", s.Command))
			sb.WriteString(fmt.Sprintf("       条件: %s\n", s.Condition))
			if s.Explain != "" {
				sb.WriteString(fmt.Sprintf("       %s\n", s.Explain))
			}
			sb.WriteString("\n")
		}
	}
}
