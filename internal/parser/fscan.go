package parser

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/span-dev/span/pkg/models"
)

// parseFscan parses fscan text output and returns structured results.
//
// fscan output patterns:
//
//	[*] 192.168.52.138:445 open
//	[+] 192.168.52.138:445 open
//	[+] 192.168.52.138:445 SMB OS: Windows Server 2008 R2
//	[+] 192.168.52.138:3389 RDP connect success [Administrator/123456]
//	[+] 192.168.52.138:3306 MySQL 5.5.62-MariaDB
//	[*] 192.168.52.138:443 close
func parseFscan(filePath string) (*ParseResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	hostMap := make(map[string]*models.Host)
	var ipOrder []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Skip banner/header lines (all-spaces or decorative chars)
		if strings.HasPrefix(line, "___") || strings.HasPrefix(line, "   ") && !strings.Contains(line, "[") {
			continue
		}

		// Skip pure status lines (no IP:port pattern)
		if !strings.Contains(line, ":") {
			continue
		}

		parseFscanLine(line, hostMap, &ipOrder)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	if len(hostMap) == 0 {
		return nil, fmt.Errorf("未解析到任何主机，请确认文件格式是否正确")
	}

	result := finalizeResult(hostMap, ipOrder, filePath)
	result.Hosts = analyzeHosts(result.Hosts)
	return result, nil
}

// parseFscanLine extracts host/port info from a single fscan output line.
func parseFscanLine(line string, hostMap map[string]*models.Host, ipOrder *[]string) {
	ip, port, remain := extractIPPort(line)
	if ip == "" || port == 0 {
		return
	}

	h := ensureHost(hostMap, ipOrder, ip)

	isOpen := isPortOpen(line)
	banner := extractBanner(line, remain)

	updateHostPort(h, port, isOpen, banner)
	extractOSFromLine(line, h)

	if isOpen {
		h.IsAlive = true
	}
}

// extractIPPort parses "IP:port" from a line.
func extractIPPort(line string) (string, int, string) {
	fields := strings.Fields(line)
	for _, f := range fields {
		if !strings.Contains(f, ":") {
			continue
		}
		// Try to split at last colon (handles IPv4:port)
		idx := strings.LastIndex(f, ":")
		if idx < 0 || idx >= len(f)-1 {
			continue
		}

		ipPart := f[:idx]
		portPart := f[idx+1:]

		// Clean trailing punctuation from port
		portPart = strings.TrimRight(portPart, ",.;:)!")

		port, err := strconv.Atoi(portPart)
		if err != nil || port < 1 || port > 65535 {
			continue
		}

		// Validate IP
		if net.ParseIP(ipPart) == nil {
			continue
		}

		// Remain = text after "IP:port"
		remainStart := strings.Index(line, f) + len(f)
		remain := ""
		if remainStart < len(line) {
			remain = strings.TrimSpace(line[remainStart:])
		}

		return ipPart, port, remain
	}
	return "", 0, ""
}

// isPortOpen determines if the line indicates an open port.
func isPortOpen(line string) bool {
	lower := strings.ToLower(line)
	if strings.Contains(lower, " open") {
		return true
	}
	if strings.Contains(lower, " close") {
		return false
	}
	// [+] lines typically mean "found something interesting" = port is open
	if strings.HasPrefix(line, "[+]") {
		return true
	}
	return true // default: assume open
}

// extractBanner tries to get service banner/version from the line.
func extractBanner(line, remain string) string {
	if remain == "" {
		return ""
	}

	lower := strings.ToLower(line)

	// SMB OS info: "SMB OS: Windows Server 2008 R2"
	if strings.Contains(lower, "smb") && strings.Contains(lower, "os:") {
		idx := strings.Index(strings.ToLower(line), "os:")
		if idx >= 0 {
			return strings.TrimSpace(line[idx+3:])
		}
	}

	if strings.Contains(lower, "mysql") {
		idx := strings.Index(lower, "mysql")
		return strings.TrimSpace(line[idx:])
	}
	if strings.Contains(lower, "mssql") {
		idx := strings.Index(lower, "mssql")
		return strings.TrimSpace(line[idx:])
	}
	if strings.Contains(lower, "ssh-") {
		idx := strings.Index(lower, "ssh-")
		start := idx
		if start > 5 {
			start -= 5
		}
		return strings.TrimSpace(line[start:])
	}
	if strings.Contains(lower, "redis") {
		return "redis"
	}
	if strings.Contains(lower, "rdp") {
		return "RDP"
	}

	// Generic: return first meaningful word after port
	parts := strings.Fields(remain)
	if len(parts) > 0 && parts[0] != "open" && parts[0] != "close" {
		return strings.Join(parts, " ")
	}

	return ""
}

// extractOSFromLine tries to extract OS hints (TTL) from fscan output lines.
// It does NOT set h.OS.Guess directly — that is done by analyzer.AnalyzeOS
// after all ports/banners are collected. This function only sets h.TTL
// so the analyzer has the TTL hint available.
func extractOSFromLine(line string, h *models.Host) {
	lower := strings.ToLower(line)

	// Only extract TTL hint from explicit OS strings like "SMB OS: Windows ..."
	// Operator precedence: && binds tighter than ||, so we group explicitly.
	if strings.Contains(lower, "smb os:") ||
		(strings.Contains(lower, "os:") && (strings.Contains(lower, "windows") || strings.Contains(lower, "linux"))) {
		idx := strings.Index(strings.ToLower(line), "os:")
		if idx < 0 {
			idx = strings.Index(line, "OS:")
		}
		if idx >= 0 {
			osStr := strings.TrimSpace(line[idx+3:])
			// Only set TTL hint; OS guess is done by analyzer.AnalyzeOS
			if strings.Contains(strings.ToLower(osStr), "windows") {
				h.TTL = 128
			} else if strings.Contains(strings.ToLower(osStr), "linux") {
				h.TTL = 64
			}
		}
	}

	// SSH banner alone is not definitive for OS (Windows can run OpenSSH)
	// Only set TTL hint if no other info is available
	if strings.Contains(lower, "openssh") && h.TTL == 0 {
		h.TTL = 64 // weak hint: could be Windows with OpenSSH
	}
}

// ensureHost returns the Host for ip, creating it if needed.
func ensureHost(hostMap map[string]*models.Host, ipOrder *[]string, ip string) *models.Host {
	if h, ok := hostMap[ip]; ok {
		return h
	}
	h := &models.Host{
		IP:      ip,
		IsAlive: false,
		Ports:   make([]models.PortInfo, 0),
	}
	hostMap[ip] = h
	*ipOrder = append(*ipOrder, ip)
	return h
}

// updateHostPort adds or updates port info for a host.
func updateHostPort(h *models.Host, port int, isOpen bool, banner string) {
	for i := range h.Ports {
		if h.Ports[i].Port == port {
			if isOpen {
				h.Ports[i].IsOpen = true
			}
			if banner != "" && h.Ports[i].Banner == "" {
				h.Ports[i].Banner = banner
			}
			return
		}
	}

	info := buildPortInfo(port, isOpen, banner)
	h.Ports = append(h.Ports, info)
}

// finalizeResult converts hostMap to ParseResult.
func finalizeResult(hostMap map[string]*models.Host, ipOrder []string, sourceFile string) *ParseResult {
	result := &ParseResult{
		Hosts:      make([]models.Host, 0, len(hostMap)),
		SourceFile: sourceFile,
	}

	for _, ip := range ipOrder {
		h := hostMap[ip]
		h.Ports = deduplicatePorts(h.Ports)
		result.Hosts = append(result.Hosts, *h)
		if h.IsAlive {
			result.AliveCount++
			result.TotalPorts += len(h.GetOpenPorts())
		}
	}

	return result
}
