package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/span-dev/span/internal/rules"
	"github.com/span-dev/span/pkg/models"
)

// AttackRule 攻击规则（内置，后续可抽到 rules 包）
type AttackRule struct {
	Port         int      // 关联端口（-1 表示不限定特定端口，基于角色）
	Service      string   // 服务名（可选，用于更精细匹配）
	Priority     int      // 优先级 1-5（数字越小越优先）
	AttackFace   string   // 攻击面描述
	Condition    string   // 触发条件
	Tools        []string // 推荐工具
	CmdKey       string   // 命令模板 Key（见 cmds.go）
	RiskNote     string   // 风险说明
	OSConstraint string   // OS 约束（"windows" / "linux" / "" 表示不限制）
}

// 内置攻击规则表（横向移动场景最小必要集）
var attackRules = []AttackRule{
	// === SMB (445) - 最高优先级 ===
	{
		Port:         445,
		Priority:     1,
		AttackFace:   "SMB 文件共享，域渗透核心入口。支持 PSExec、哈希传递、MS17-010",
		Condition:    "有凭证或哈希",
		Tools:        []string{"impacket-psexec", "impacket-smbexec", "msf-psexec"},
		CmdKey:       "smb_psexec",
		RiskNote:     "⚠️ 优先尝试：SMB 是域环境横向移动最高频入口",
		OSConstraint: "windows",
	},
	{
		Port:         445,
		Priority:     2,
		AttackFace:   "SMB 无凭证时尝试哈希传递（Pass-the-Hash）",
		Condition:    "有哈希（无明文密码）",
		Tools:        []string{"impacket-psexec", "msf-pth"},
		CmdKey:       "smb_pth",
		RiskNote:     "⚠️ 需要 NTLM 哈希（通常从 DCSync 或本地 SAM 获取）",
		OSConstraint: "windows",
	},

	// === RDP (3389) - 高优先级 ===
	{
		Port:         3389,
		Priority:     2,
		AttackFace:   "RDP 远程桌面，图形化控制",
		Condition:    "有凭证",
		Tools:        []string{"rdesktop", "xfreerdp", "msf-rdp"},
		CmdKey:       "rdp_connect",
		RiskNote:     "⚠️ 登录可能留下日志；建议用受损凭据，避免用高权限账户",
		OSConstraint: "windows",
	},

	// === WinRM (5985) - 高优先级 ===
	{
		Port:         5985,
		Priority:     2,
		AttackFace:   "WinRM 远程管理，支持 PowerShell 远程执行",
		Condition:    "有凭证",
		Tools:        []string{"evil-winrm", "impacket-wmiexec"},
		CmdKey:       "winrm_evilwinrm",
		RiskNote:     "⚠️ 比 PSExec 更隐蔽（不创建服务）；优先推荐",
		OSConstraint: "windows",
	},

	// === LDAP (389) - 信息收集 ===
	{
		Port:       389,
		Priority:   2,
		AttackFace: "LDAP 域信息查询，支持匿名绑定（若未禁用）",
		Condition:  "无凭证（尝试匿名）或有凭证",
		Tools:      []string{"ldapsearch", "impacket-rpcdump"},
		CmdKey:     "ldap_query",
		RiskNote:   "⚠️ 信息收集阶段核心；匿名绑定若开启可直接枚举域用户/组",
	},

	// === MSSQL (1433) - 数据库利用 ===
	{
		Port:       1433,
		Priority:   3,
		AttackFace: "MSSQL 数据库，尝试 SA 弱口令或 XP_CMDSHELL 提权",
		Condition:  "有 SA 凭证或无凭证（弱口令）",
		Tools:      []string{"impacket-mssqlclient", "sqsh"},
		CmdKey:     "mssql_client",
		RiskNote:   "⚠️ 若 XP_CMDSHELL 开启，可直接执行系统命令（需 SA 权限）",
	},

	// === MySQL (3306) - 数据库利用 ===
	{
		Port:       3306,
		Priority:   3,
		AttackFace: "MySQL 数据库，尝试弱口令或 UDF 提权",
		Condition:  "有凭证或无凭证（弱口令）",
		Tools:      []string{"mysql-client", "sqlmap"},
		CmdKey:     "mysql_client",
		RiskNote:   "⚠️ 数据库权限通常受限；若以 SYSTEM 运行 MySQL 服务可尝试提权",
	},

	// === Redis (6379) - 未授权访问 ===
	{
		Port:         6379,
		Priority:     3,
		AttackFace:   "Redis 未授权访问或弱口令，可写 SSH 公钥或 crontab 反弹",
		Condition:    "无凭证（未开启认证）或有弱口令",
		Tools:        []string{"redis-cli"},
		CmdKey:       "redis_exploit",
		RiskNote:     "⚠️ Linux 环境常见；Windows 版 Redis 也可通过绝对路径写 WebShell",
		OSConstraint: "linux",
	},

	// === SSH (22) - 远程登录 ===
	{
		Port:         22,
		Priority:     3,
		AttackFace:   "SSH 远程登录，尝试弱口令或密钥复用",
		Condition:    "有凭证或私钥文件",
		Tools:        []string{"ssh-client"},
		CmdKey:       "ssh_connect",
		RiskNote:     "⚠️ 若拿到私钥文件（如 id_rsa），可直接登录而无需密码",
		OSConstraint: "linux",
	},

	// === Kerberos (88) - 域用户枚举 ===
	{
		Port:       88,
		Priority:   4,
		AttackFace: "Kerberos 服务，可枚举域用户（AS-REP Roasting）",
		Condition:  "无凭证（用户枚举）或有凭证（TGT 请求）",
		Tools:      []string{"impacket-GetNPUsers", "impacket-GetUserSPNs"},
		CmdKey:     "kerberos_enum",
		RiskNote:   "⚠️ 信息收集阶段；AS-REP Roasting 可获取无 Kerberos 预认证的用户的哈希",
	},
}

// AnalyzeAttacks 对单台主机进行攻击面分析，返回按优先级排序的攻击建议列表
func AnalyzeAttacks(host *models.Host) []models.AttackSuggestion {
	suggestions := make([]models.AttackSuggestion, 0)

	// 1. 基于开放端口匹配攻击规则
	for _, portInfo := range host.Ports {
		if !portInfo.IsOpen {
			continue
		}

		for _, rule := range attackRules {
			// 匹配端口
			if rule.Port != portInfo.Port && rule.Port != -1 {
				continue
			}

			// OS 约束检查
			if rule.OSConstraint != "" {
				osGuess := ""
				if host.OS.Guess != "" {
					osGuess = strings.ToLower(host.OS.Guess)
				}
				isWindows := strings.Contains(osGuess, "windows")
				isLinux := strings.Contains(osGuess, "linux")

				if rule.OSConstraint == "windows" && !isWindows {
					continue
				}
				if rule.OSConstraint == "linux" && !isLinux {
					continue
				}
			}

			// 生成命令模板
			commands := generateCommands(rule.CmdKey, host.IP, portInfo.Port)
			// Explain 只包含攻击面描述和风险说明，不包含"条件"和"推荐工具"（由 FormatSuggestions 统一输出）
			explain := fmt.Sprintf("%s\n  %s",
				rule.AttackFace, rule.RiskNote)

			suggestion := models.AttackSuggestion{
				Service:   portInfo.Service,
				Priority:  rule.Priority,
				Tool:      strings.Join(rule.Tools, ", "), // 保存所有推荐工具（逗号分隔）
				Command:   commands,
				Condition: rule.Condition,
				Explain:   explain,
			}
			suggestions = append(suggestions, suggestion)
		}
	}

	// 2. 基于角色补充攻击建议
	for _, role := range host.Roles {
		roleSuggestions := analyzeByRole(role.Role, host)
		suggestions = append(suggestions, roleSuggestions...)
	}

	// 3. 按优先级排序（数字越小越靠前）
	sort.Slice(suggestions, func(i, j int) bool {
		return suggestions[i].Priority < suggestions[j].Priority
	})

	return suggestions
}

// analyzeByRole 基于角色生成额外攻击建议
func analyzeByRole(role string, host *models.Host) []models.AttackSuggestion {
	switch role {
	case "域控制器 (DC)":
		// 域控额外建议：DCSync、Kerberoasting
		return []models.AttackSuggestion{
			{
				Service:   "domain",
				Priority:  2,
				Tool:      "impacket-secretsdump",
				Command:   generateCommands("domain_dcsync", host.IP, 0),
				Condition: "有域管凭证或哈希",
				Explain:   "域控核心攻击：若有域管凭证，直接 DCSync 获取所有用户哈希\n  ⚠️ 最高价值目标；DCSync 后可控整个域",
			},
		}
	default:
		return nil
	}
}

// generateCommands 根据 CmdKey 生成命令模板（从 rules 包获取）
func generateCommands(cmdKey string, target string, port int) string {
	if cmdTemplate := rules.GetCommandTemplate(cmdKey); cmdTemplate != nil {
		// 返回第一个命令模板（替换占位符）
		if len(cmdTemplate.Templates) > 0 {
			cmd := cmdTemplate.Templates[0]
			cmd = strings.ReplaceAll(cmd, "{target}", target)
			cmd = strings.ReplaceAll(cmd, "{port}", fmt.Sprintf("%d", port))
			// 保留 {user}, {pass}, {hash} 等占位符，供用户替换
			return cmd
		}
	}

	// 兜底：返回提示
	return "# 命令模板未找到，请手动构造"
}

// FormatSuggestions 格式化攻击建议列表（供输出模块调用）
func FormatSuggestions(suggestions []models.AttackSuggestion, verbose bool) string {
	if len(suggestions) == 0 {
		return "    [-] 未发现明显攻击面\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("    [攻击面] 发现 %d 个攻击建议（按优先级排序）:\n\n", len(suggestions)))

	for i, s := range suggestions {
		if i >= 5 && !verbose {
			sb.WriteString(fmt.Sprintf("    ... 还有 %d 个建议（使用 -v 查看全部）\n", len(suggestions)-5))
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

		sb.WriteString(fmt.Sprintf("    %s 优先级 %d | %s (端口 %s)\n", priorityIcon, s.Priority, s.Service, s.Tool))
		sb.WriteString(fmt.Sprintf("       命令: %s\n", s.Command))
		sb.WriteString(fmt.Sprintf("       条件: %s\n", s.Condition))
		sb.WriteString(fmt.Sprintf("       推荐工具: %s\n", s.Tool))
		if s.Explain != "" {
			sb.WriteString(fmt.Sprintf("       %s\n", s.Explain))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
