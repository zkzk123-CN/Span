package parser

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/span-dev/span/pkg/models"
)

// ==================== Nmap Normal Format Parser ====================

// parseNmapNormal parses nmap "-oN" (normal human-readable) output.
func parseNmapNormal(filePath string) (*ParseResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	hostMap := make(map[string]*models.Host)
	var ipOrder []string

	var currentHost *models.Host

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// "Nmap scan report for 192.168.52.138"
		// "Nmap scan report for DC (192.168.52.138)"
		if strings.HasPrefix(line, "Nmap scan report for ") {
			if currentHost != nil {
				finalizeHostPorts(currentHost)
			}
			ip := extractIPFromNmapLine(line)
			if ip != "" {
				currentHost = ensureHost(hostMap, &ipOrder, ip)
			}
			continue
		}

		// "Host is up" -> mark alive
		if strings.HasPrefix(line, "Host is up") && currentHost != nil {
			currentHost.IsAlive = true
			// Extract TTL if present: "Host is up (0.010s latency)."
			// TTL is not in this line for normal output
			continue
		}

		// PORT line: "22/tcp   open  ssh  OpenSSH 7.4"
		if strings.Contains(line, "/tcp") || strings.Contains(line, "/udp") {
			parseNmapPortLine(line, currentHost)
			continue
		}

		// Service Info / OS clues
		if strings.Contains(line, "Service Info:") && currentHost != nil {
			extractOSFromNmapServiceInfo(line, currentHost)
		}
		if strings.Contains(line, "smb-os-discovery") && currentHost != nil {
			extractOSFromNmapScript(line, currentHost)
		}
		if strings.Contains(line, "OS details:") && currentHost != nil {
			extractOSFromNmapOSDetails(line, currentHost)
		}
	}

	// Save last host
	if currentHost != nil {
		finalizeHostPorts(currentHost)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	if len(hostMap) == 0 {
		return nil, fmt.Errorf("未解析到任何主机")
	}

	result := finalizeResult(hostMap, ipOrder, filePath)
	result.Hosts = analyzeHosts(result.Hosts)
	return result, nil
}

// extractIPFromNmapLine extracts IP from "Nmap scan report for ..." line.
func extractIPFromNmapLine(line string) string {
	// Remove prefix
	rest := strings.TrimPrefix(line, "Nmap scan report for ")
	rest = strings.TrimSpace(rest)

	// Case: "DC (192.168.52.138)"
	if strings.HasSuffix(rest, ")") && strings.Contains(rest, "(") {
		start := strings.LastIndex(rest, "(")
		end := strings.LastIndex(rest, ")")
		if start >= 0 && end >= 0 {
			ip := rest[start+1 : end]
			ip = strings.TrimSpace(ip)
			if isLikelyIP(ip) {
				return ip
			}
		}
	}

	// Case: "192.168.52.138"
	// Could also be "DC" (hostname only) - check if it's an IP
	if isLikelyIP(rest) {
		return rest
	}

	// Return empty if not an IP (hostname only, skip for now)
	return ""
}

// isLikelyIP does a quick check if string looks like an IPv4 address.
func isLikelyIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// parseNmapPortLine parses a port line from nmap normal output.
// Format: "22/tcp   open  ssh  OpenSSH 7.4"
func parseNmapPortLine(line string, h *models.Host) {
	if h == nil {
		return
	}
	if strings.HasPrefix(line, "PORT") {
		return // header line
	}

	fields := strings.Fields(line)
	if len(fields) < 3 {
		return
	}

	// Parse "22/tcp"
	protoParts := strings.Split(fields[0], "/")
	if len(protoParts) < 2 {
		return
	}
	port, err := strconv.Atoi(protoParts[0])
	if err != nil || port < 1 || port > 65535 {
		return
	}

	state := fields[1]
	isOpen := strings.ToLower(state) == "open"

	// Build banner from service + version
	banner := ""
	if len(fields) >= 3 {
		banner = fields[2] // service name
		if len(fields) > 3 {
			banner += " " + strings.Join(fields[3:], " ")
		}
	}

	updateHostPort(h, port, isOpen, banner)

	if isOpen {
		h.IsAlive = true
	}
}

// extractOSFromNmapServiceInfo extracts OS from "Service Info: OS: Windows..." line.
func extractOSFromNmapServiceInfo(line string, h *models.Host) {
	lower := strings.ToLower(line)
	idx := strings.Index(lower, "os:")
	if idx < 0 {
		return
	}
	// idx in lowercased line matches original because "os:" / "OS:" have same length
	osStr := strings.TrimSpace(line[idx+3:])
	osStr = strings.TrimRight(osStr, ",;|")
	if osStr != "" {
		h.OS.Guess = osStr
		h.OS.Confidence = "medium"
		h.OS.Method = "Service Info (nmap)"
	}
}

// extractOSFromNmapScript extracts OS from nmap script output.
func extractOSFromNmapScript(line string, h *models.Host) {
	lower := strings.ToLower(line)
	idx := strings.Index(lower, "os:")
	if idx < 0 {
		return
	}
	osStr := strings.TrimSpace(line[idx+3:])
	osStr = strings.TrimRight(osStr, ",;|")
	if osStr != "" {
		h.OS.Guess = osStr
		h.OS.Confidence = "high"
		h.OS.Method = "Nmap Script (smb-os-discovery)"
	}
}

// extractOSFromNmapOSDetails extracts OS from "OS details:" line.
func extractOSFromNmapOSDetails(line string, h *models.Host) {
	idx := strings.Index(line, "OS details:")
	if idx < 0 {
		return
	}
	osStr := strings.TrimSpace(line[idx+11:])
	osStr = strings.TrimRight(osStr, ".")
	if osStr != "" && h.OS.Guess == "" {
		h.OS.Guess = osStr
		h.OS.Confidence = "medium"
		h.OS.Method = "OS Detection (nmap)"
	}
}

// finalizeHostPorts deduplicates ports for a host before saving.
func finalizeHostPorts(h *models.Host) {
	if h == nil {
		return
	}
	h.Ports = deduplicatePorts(h.Ports)
}

// ==================== Nmap XML Parser ====================

// parseNmapXML parses nmap "-oX" (XML) output.
func parseNmapXML(filePath string) (*ParseResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	var nmapRun NmapRun
	if err := xml.NewDecoder(file).Decode(&nmapRun); err != nil {
		return nil, fmt.Errorf("解析 Nmap XML 失败: %v", err)
	}

	hostMap := make(map[string]*models.Host)
	var ipOrder []string

	for _, hostXML := range nmapRun.Hosts {
		ip := ""
		for _, addr := range hostXML.Addresses {
			if addr.AddrType == "ipv4" {
				ip = addr.Addr
				break
			}
		}
		if ip == "" {
			continue
		}

		h := ensureHost(hostMap, &ipOrder, ip)
		h.IsAlive = hostXML.Status.State == "up"

		for _, portXML := range hostXML.Ports.Ports {
			if portXML.State.State != "open" {
				continue
			}
			h.IsAlive = true

			banner := ""
			if portXML.Service.Name != "" {
				banner = portXML.Service.Name
				if portXML.Service.Product != "" {
					banner += " " + portXML.Service.Product
				}
				if portXML.Service.Version != "" {
					banner += " " + portXML.Service.Version
				}
			}

			updateHostPort(h, portXML.PortID, true, banner)
		}

		// Parse OS detection
		if len(hostXML.OS.OSMatches) > 0 {
			best := hostXML.OS.OSMatches[0]
			h.OS.Guess = best.Name
			h.OS.Confidence = "high"
			h.OS.Method = "Nmap OS Detection"
		}
	}

	if len(hostMap) == 0 {
		return nil, fmt.Errorf("未解析到任何主机")
	}

	result := finalizeResult(hostMap, ipOrder, filePath)
	result.Hosts = analyzeHosts(result.Hosts)
	return result, nil
}

// ==================== Nmap XML Structs ====================

// NmapRun is the root element of nmap XML output.
type NmapRun struct {
	XMLName xml.Name  `xml:"nmaprun"`
	Hosts   []XMLHost `xml:"host"`
}

// XMLHost represents a <host> element.
type XMLHost struct {
	Status    XMLStatus    `xml:"status"`
	Addresses []XMLAddress `xml:"address"`
	Ports     XMLPorts     `xml:"ports"`
	OS        XMLOS        `xml:"os"`
}

type XMLStatus struct {
	State string `xml:"state,attr"`
}

type XMLAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type XMLPorts struct {
	Ports []XMLPort `xml:"port"`
}

type XMLPort struct {
	PortID  int        `xml:"portid,attr"`
	State   XMLPState  `xml:"state"`
	Service XMLService `xml:"service"`
}

type XMLPState struct {
	State string `xml:"state,attr"`
}

type XMLService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

type XMLOS struct {
	OSMatches []XMLOSMatch `xml:"osmatch"`
}

type XMLOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}
