# Span

> **fscan 告诉你内网有什么，Span 告诉你这些是什么、怎么打、先打哪个。**

Span 是一款内网横向移动专用扫描与分析工具。它不是 fscan 的替代品，而是互补搭档——fscan 负责快速发现，Span 负责深度分析和攻击建议。

## 特性

- **精准扫描**：只扫横向移动相关端口（18个），不做全端口扫描
- **OS 识别**：基于 TTL + 端口组合 + Banner 的启发式推断（三方加权投票）
- **角色推断**：通过端口组合判断机器角色（域控/数据库/跳板机/普通成员），Top-3 候选
- **攻击建议**：自动生成可直接执行的命令模板（Impacket/MSF/evil-winrm/rdesktop/ldapsearch/mysql/redis）
- **分析模式**：解析 fscan/nmap 输出文件，继承分析能力
- **教学解释**：每条建议附带原理说明，适合学习理解
- **单文件部署**：静态编译 822KB，无外部依赖，上传到边界机直接执行
- **隐蔽模式**：默认低并发（10 线程），减少告警
- **终端+文件双输出**：终端带 ANSI 颜色，文件纯文本（`span_result.txt`）

## 快速开始

```bash
# 扫描整个网段
span 192.168.52.0/24

# 扫描单台主机
span 192.168.52.138

# 从文件读取目标
span -f targets.txt

# 分析 fscan 输出（支持 fscan/nmap 格式，自动检测）
span --analyze fscan_output.txt

# 分析 nmap 输出
span --analyze nmap_output.txt

# 高速扫描
span 192.168.52.0/24 -threads 100

# 详细模式（含匹配端口、候选角色、Banner 信息）
span 192.168.52.0/24 -v

# 仅显示 Critical 级别攻击面
span 192.168.52.0/24 -critical-only
```

## 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `[target]` | 目标 IP 或 CIDR（如 `192.168.52.0/24`） | 必填或 `-f` |
| `-f` | 目标文件，每行一个 IP/CIDR | - |
| `-threads` | 并发线程数 | 10 |
| `-timeout` | 端口超时（毫秒） | 2000 |
| `--analyze` | 分析模式：解析 fscan/nmap 输出文件 | - |
| `-o` | 结果输出文件路径 | `span_result.txt` |
| `-v` | 详细模式 | false |
| `-critical-only` | 仅显示 Critical 级别攻击面 | false |
| `--ports` | 自定义端口列表（逗号分隔） | 18个默认端口 |
| `-h` | 显示帮助 | - |

## 使用场景

### 场景 1：内网横向移动

```bash
# 1. 用 Span 扫描发现
span 192.168.52.0/24 -v

# 2. 查看输出文件
cat span_result.txt

# 3. 根据攻击建议行动
# 例如: evil-winrm -i 192.168.52.138 -u Administrator -p 'P@ssw0rd'
```

### 场景 2：分析 fscan 结果

```bash
# fscan 扫完了，用 Span 做深度分析
span --analyze fscan_result.txt -v
# Span 自动识别 OS、角色、生成攻击建议，无需重复扫描
```

### 场景 3：分析 nmap 结果

```bash
nmap -p- -sV -O 192.168.52.0/24 -oN nmap_output.txt
span --analyze nmap_output.txt
# 支持普通格式 (-oN) 和 XML 格式 (-oX)
```

## 输出示例

```
[+] 192.168.52.138 (TTL=128)
    [OS]  Windows (Banner 确认) (置信度: high | 方法: TTL(128)+端口组合+Banner)
    [角色] Windows 跳板机/边界机 (置信度: 79%)
          └─ Windows 双网卡机器或跳板机 (RDP + SMB 开放)
    --------------------------------------------------
    端口       服务           风险         说明
    ----     ----         ----       ----
    445      smb          [Critical] SMB 文件共享 / 域渗透核心入口
    3389     rdp          [High]     RDP 远程桌面
    5985     winrm        [High]     WinRM HTTP 远程管理

    [攻击面] 发现 5 个攻击建议（按优先级排序）:

    [!] 优先级 1 | smb (端口 impacket-psexec)
       命令: psexec.py {domain}/{user}:{pass}@192.168.52.138
       条件: 有凭证或哈希
       SMB 文件共享，域渗透核心入口。支持 PSExec、哈希传递、MS17-010

    [*] 优先级 2 | rdp (端口 rdesktop)
       命令: rdesktop -u {user} -p {pass} 192.168.52.138
       条件: 有凭证
```

## 扫描端口（18个）

| 端口 | 服务 | 风险等级 | 说明 |
|------|------|---------|------|
| 22 | SSH | High | SSH 远程登录 |
| 53 | DNS | High | DNS 域名解析（域控标志） |
| 88 | Kerberos | Critical | Kerberos 认证（域控标志） |
| 135 | RPC | High | RPC / WMI 入口 |
| 139 | NetBIOS | Medium | NetBIOS 会话服务 |
| 389 | LDAP | Critical | LDAP 目录服务（域控标志） |
| 445 | SMB | Critical | SMB 文件共享 / 域渗透核心入口 |
| 636 | LDAPS | Critical | LDAPS 安全 LDAP |
| 1433 | MSSQL | Critical | Microsoft SQL Server |
| 3306 | MySQL | Medium | MySQL 数据库 |
| 3389 | RDP | High | RDP 远程桌面 |
| 5985 | WinRM | High | WinRM HTTP 远程管理 |
| 5986 | WinRM-SSL | High | WinRM HTTPS 远程管理 |
| 6379 | Redis | Critical | Redis 键值数据库（未授权访问风险） |
| 7001 | WebLogic | Critical | WebLogic 应用服务器 |
| 8008 | Tomcat | High | Tomcat 备用端口 |
| 8099 | Custom | Medium | 自定义 Web 服务 |
| 8898 | Custom | Medium | 自定义服务 |

## 角色推断规则

| 角色 | 必备端口 | 加分端口 |
|------|---------|---------|
| 域控制器 (DC) | 53, 88, 389 | 445, 636 |
| Exchange 邮件服务器 | 25, 80, 443, 587 | 143, 993, 389 |
| MSSQL 数据库服务器 | 1433 | 445, 3389, 135 |
| MySQL 数据库服务器 | 3306 | 22, 445, 3389 |
| Redis 缓存服务器 | 6379 | 22 |
| WebLogic 应用服务器 | 7001 | 80, 443 |
| Windows 跳板机/边界机 | 3389, 445 | 135, 139, 5985 |
| Linux SSH 服务器 | 22 | 80, 443, 3306 |
| 域成员工作站 | 135, 445, 139 | 3389, 5985 |
| 通用 Web 服务器 | 80 | 443, 8080 |

## 攻击命令模板

Span 内置常见横向移动工具的命令模板（占位符：`{target}`, `{user}`, `{pass}`, `{hash}`, `{domain}`）：

| 攻击面 | 工具 | 示例命令 |
|--------|------|---------|
| SMB (445) | impacket-psexec | `psexec.py {domain}/{user}:{pass}@{target}` |
| SMB PtH | impacket-psexec | `psexec.py -hashes :{ntlm} {domain}/{user}@{target}` |
| RDP (3389) | rdesktop | `rdesktop -u {user} -p {pass} {target}` |
| WinRM (5985) | evil-winrm | `evil-winrm -i {target} -u {user} -p {pass}` |
| LDAP (389) | ldapsearch | `ldapsearch -x -H ldap://{target} -D '{user}' -W` |
| MSSQL (1433) | mssqlclient.py | `mssqlclient.py {user}:{pass}@{target} -windows-auth` |
| MySQL (3306) | mysql-client | `mysql -h {target} -u {user} -p{pass}` |
| Redis (6379) | redis-cli | `redis-cli -h {target}` |
| SSH (22) | ssh-client | `ssh {user}@{target}` |
| Kerberos (88) | GetNPUsers.py | `GetNPUsers.py {domain}/ -dc-ip {target} -request` |
| DC DCSync | secretsdump.py | `secretsdump.py {domain}/{user}:{pass}@{target}` |

## OS 检测方法

Span 使用三类证据加权投票推断操作系统：

| 证据源 | 权重 | 方法 |
|--------|------|------|
| TTL | 1 | TTL ≥ 118 → Windows; TTL ≤ 68 → Linux |
| 端口组合 | 2 | 445+3389+5985 → Windows; 22+3306+6379 → Linux |
| Banner | 3 | "Microsoft/Windows/SMB" → Windows; "Ubuntu/CentOS/Debian" → Linux |

- SSH Banner 不单独作为 Linux 证据（Windows 2019+ 也运行 OpenSSH）
- 多方一致时置信度为 **high**，存在分歧时保留最具体的判断

## 编译

```bash
# 编译当前平台
make build

# UPX 压缩（最终 822KB）
make compress

# 交叉编译 Windows
make build-windows

# 交叉编译 Linux
make build-linux

# 全平台
make build-all
```

编译要求：Go ≥ 1.22，`CGO_ENABLED=0`（静态编译），UPX（可选，用于压缩）。

## 项目结构

```
span/
├── cmd/span/          # CLI 入口，参数解析，流程串联
├── internal/
│   ├── scanner/       # TCP 存活探测、端口扫描、Banner 抓取
│   ├── analyzer/      # OS 启发式判断、角色推断、攻击面分析
│   ├── parser/        # fscan/nmap 输出解析（--analyze 模式）
│   ├── output/        # 终端表格输出、文件输出
│   └── rules/         # 规则库（端口映射、角色规则、OS 启发式、命令模板）
├── pkg/models/        # 数据模型定义
├── bin/               # 编译输出
├── Makefile
├── README.md
└── LICENSE
```

## 靶场环境

开发测试使用以下靶场：

| 主机 | IP | 系统 | 角色 |
|------|------|------|------|
| stu1（边界机） | 192.168.30.128 / 192.168.52.143 | Win7 Pro SP1 | 双网卡跳板 |
| owa（域控） | 192.168.52.138 | Server 2008 R2 DC | DC + Exchange |
| Server 2003 | 192.168.52.141 | Server 2003 Ent | 域成员 |

攻击机：Kali Linux 2025.4, 192.168.30.143

## 免责声明

**本工具仅供授权的渗透测试和安全研究使用。未经目标系统所有者明确书面授权，使用本工具进行扫描或攻击属于违法行为，后果自负。**

工具生成的所有建议均为基于端口扫描的推测，可能存在误报。请结合实际情况判断。

## License

MIT
