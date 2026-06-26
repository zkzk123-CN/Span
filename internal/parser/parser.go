// Package parser provides parsers for external tool outputs (fscan, nmap).
// After parsing, the results are converted to []models.Host and fed into
// the existing analyzer pipeline (Phase 2 + Phase 3).
package parser

import (
	"fmt"
	"os"
	"strings"

	"github.com/span-dev/span/internal/analyzer"
	"github.com/span-dev/span/internal/rules"
	"github.com/span-dev/span/pkg/models"
)

// ParseResult holds the parsed scan results ready for analysis.
type ParseResult struct {
	Hosts      []models.Host
	AliveCount int
	TotalPorts int
	SourceFile string
}

// ParseFile auto-detects the file type and dispatches to the appropriate parser.
// Supported formats: fscan text output, nmap normal (-oN), nmap XML (-oX).
func ParseFile(filePath string) (*ParseResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	// Read first 2KB to detect format
	buf := make([]byte, 2048)
	n, _ := file.Read(buf)
	if n == 0 {
		return nil, fmt.Errorf("文件为空")
	}

	// Reset file pointer
	file.Seek(0, 0)

	content := strings.ToLower(string(buf[:n]))

	// Detect format
	if strings.Contains(content, "<?xml") || strings.Contains(content, "<nmaprun") {
		fmt.Printf("[*] 检测到 Nmap XML 格式\n")
		return parseNmapXML(filePath)
	}
	if strings.Contains(content, "nmap scan report") || strings.Contains(content, "# nmap") {
		fmt.Printf("[*] 检测到 Nmap 普通格式\n")
		return parseNmapNormal(filePath)
	}
	if strings.Contains(content, "fscan") || (strings.Contains(content, "[*]") && strings.Contains(content, "open")) {
		fmt.Printf("[*] 检测到 fscan 格式\n")
		return parseFscan(filePath)
	}

	// Fallback: try fscan format (most common for our use case)
	fmt.Printf("[*] 未识别格式，尝试按 fscan 格式解析...\n")
	return parseFscan(filePath)
}

// analyzeHosts runs Phase 2 (OS + role) and Phase 3 (attack analysis)
// on the parsed hosts.
func analyzeHosts(hosts []models.Host) []models.Host {
	for i := range hosts {
		h := &hosts[i]
		if !h.IsAlive {
			continue
		}

		openPorts := h.GetOpenPorts()

		// Build banner map for OS detection
		bannerMap := make(map[int]string)
		for _, p := range openPorts {
			if p.Banner != "" {
				bannerMap[p.Port] = p.Banner
			}
		}

		// Phase 2: OS detection
		// If the parser already found OS info (e.g. nmap OS detection),
		// keep it but supplement with heuristic hints.
		heuristicOS := analyzer.AnalyzeOS(h.TTL, openPorts, bannerMap)
		if h.OS.Guess == "" {
			h.OS = heuristicOS
		} else if h.OS.Confidence == "high" {
			// Parser already has high-confidence OS (e.g. nmap -O),
			// append heuristic hints for transparency
			h.OS.Hints = append(h.OS.Hints, heuristicOS.Hints...)
		} else {
			// Parser had low/medium confidence, prefer heuristic if better
			if heuristicOS.Confidence == "high" {
				h.OS = heuristicOS
			} else {
				h.OS.Hints = append(h.OS.Hints, heuristicOS.Hints...)
			}
		}

		h.Roles = analyzer.AnalyzeRole(openPorts)

		// Phase 3: attack surface analysis
		h.Suggestions = analyzer.AnalyzeAttacks(h)
	}
	return hosts
}

// buildPortInfo converts a port number to models.PortInfo using the rules database.
func buildPortInfo(port int, isOpen bool, banner string) models.PortInfo {
	info := models.PortInfo{
		Port:   port,
		IsOpen: isOpen,
		Banner: banner,
	}

	// Look up service info from rules
	if rule := rules.GetPortRule(port); rule != nil {
		info.Service = rule.Service
		info.Risk = rule.Risk
	} else {
		info.Service = "unknown"
		info.Risk = models.RiskLow
	}

	return info
}

// deduplicatePorts ensures each port appears only once in the host's port list.
func deduplicatePorts(ports []models.PortInfo) []models.PortInfo {
	seen := make(map[int]bool)
	result := make([]models.PortInfo, 0, len(ports))
	for _, p := range ports {
		if !seen[p.Port] {
			seen[p.Port] = true
			result = append(result, p)
		} else if p.Banner != "" {
			// Merge banner into existing entry
			for i := range result {
				if result[i].Port == p.Port {
					if result[i].Banner == "" {
						result[i].Banner = p.Banner
					}
					result[i].IsOpen = result[i].IsOpen || p.IsOpen
					break
				}
			}
		}
	}
	return result
}
