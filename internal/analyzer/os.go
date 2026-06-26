// Package analyzer provides OS guessing and role inference for scan results.
package analyzer

import (
	"fmt"
	"strings"

	"github.com/span-dev/span/internal/rules"
	"github.com/span-dev/span/pkg/models"
)

// AnalyzeOS performs heuristic OS detection based on TTL, open ports, and banners.
func AnalyzeOS(ttl int, ports []models.PortInfo, bannerMap map[int]string) models.OSGuess {
	oss := models.OSGuess{
		Guess:      "未知",
		Confidence: "low",
		Method:     "无数据",
		TTLValue:   ttl,
	}

	if ttl <= 0 && len(ports) == 0 {
		return oss
	}

	// Step1: TTL-based OS classification
	ttlGuess, ttlConf := classifyByTTL(ttl)

	// Step2: Port-based hints
	portGuess, portConf := classifyByPorts(ports)

	// Step3: Banner-based hints
	bannerGuess, bannerConf := classifyByBanners(bannerMap)

	// Combine all evidence (weighted decision)
	bestGuess := combineOSEvidence(ttl, ttlGuess, ttlConf, portGuess, portConf, bannerGuess, bannerConf)
	oss.Guess = bestGuess.guess
	oss.Confidence = bestGuess.confidence
	oss.Method = bestGuess.method
	oss.Hints = bestGuess.hints

	return oss
}

type osEvidence struct {
	guess      string
	confidence string // "high" | "medium" | "low"
	method     string
	hints      []string
}

func classifyByTTL(ttl int) (string, string) {
	if ttl <= 0 {
		return "", ""
	}

	hints := rules.DefaultOSHints()
	for _, h := range hints {
		if ttl >= h.TTLMin && ttl <= h.TTLMax {
			// Only match if no specific port requirement (pure TTL rule)
			if len(h.Ports) == 0 && len(h.BannerKw) == 0 {
				return h.Guess, h.Confidence
			}
		}
	}

	// Generic TTL classification
	if ttl >= 118 && ttl <= 132 {
		return "Windows", "medium"
	} else if ttl >= 60 && ttl <= 68 {
		return "Linux", "medium"
	} else if ttl >= 240 {
		return "网络设备/Unix", "low"
	} else if ttl >= 32 && ttl <= 64 {
		return "Linux/Windows (TTL 不明确)", "low"
	}

	return fmt.Sprintf("未知 (TTL=%d)", ttl), "low"
}

func classifyByPorts(ports []models.PortInfo) (string, string) {
	if len(ports) == 0 {
		return "", ""
	}

	openPortNums := make([]int, 0, len(ports))
	for _, p := range ports {
		openPortNums = append(openPortNums, p.Port)
	}

	// Check against OS hint rules that have port requirements
	hints := rules.DefaultOSHints()
	for _, h := range hints {
		if len(h.Ports) == 0 {
			continue
		}
		if portsMatch(openPortNums, h.Ports, 0.5) { // at least 50% of hint ports found
			return h.Guess, h.Confidence
		}
	}

	// Heuristic: Windows-specific port combinations
	windowsPorts := []int{135, 139, 445, 3389, 5985, 5986}
	wCount := countMatches(openPortNums, windowsPorts)
	linuxPorts := []int{22, 80, 443, 3306, 6379, 8080}
	lCount := countMatches(openPortNums, linuxPorts)

	if wCount >= 2 {
		return "Windows (多端口匹配)", "medium"
	} else if lCount >= 2 && wCount < 2 {
		return "Linux (多端口匹配)", "medium"
	}

	return "", ""
}

func classifyByBanners(bannerMap map[int]string) (string, string) {
	if len(bannerMap) == 0 {
		return "", ""
	}

	bannersJoined := ""
	for _, b := range bannerMap {
		bannersJoined += b + " "
	}
	lower := strings.ToLower(bannersJoined)

	// 1. Direct Windows detection (strongest signal, checked first)
	// "microsoft" / "windows" in any banner is definitive
	if strings.Contains(lower, "microsoft") || strings.Contains(lower, "windows") {
		return "Windows (Banner 确认)", "high"
	}

	// 2. Rule-based banner keyword matching
	// Collect Windows and Linux matches separately, then pick by priority.
	// Windows wins because Windows can run OpenSSH, but Linux rarely runs SMB.
	hints := rules.DefaultOSHints()
	var winGuess, winConf, linGuess, linConf string
	for _, h := range hints {
		if len(h.BannerKw) == 0 {
			continue
		}
		matched := false
		for _, kw := range h.BannerKw {
			if strings.Contains(lower, strings.ToLower(kw)) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		gLower := strings.ToLower(h.Guess)
		if strings.Contains(gLower, "windows") && winGuess == "" {
			winGuess = h.Guess
			winConf = h.Confidence
		} else if strings.Contains(gLower, "linux") && linGuess == "" {
			linGuess = h.Guess
			linConf = h.Confidence
		}
	}

	if winGuess != "" {
		return winGuess, winConf
	}
	if linGuess != "" {
		return linGuess, linConf
	}

	// 3. Direct Linux distribution detection
	if strings.Contains(lower, "ubuntu") {
		return "Ubuntu Linux", "high"
	}
	if strings.Contains(lower, "centos") || strings.Contains(lower, "red hat") || strings.Contains(lower, "rhel") {
		return "CentOS/RHEL Linux", "high"
	}
	if strings.Contains(lower, "debian") {
		return "Debian Linux", "high"
	}

	// 4. SSH banner only (weakest — could be Windows with OpenSSH)
	if strings.Contains(lower, "openssh") || strings.Contains(lower, "ssh-2.0") {
		return "Linux/Unix (SSH Banner)", "medium"
	}

	return "", ""
}

func combineOSEvidence(ttl int, ttlG, ttlC, portG, portC, banG, banC string) osEvidence {
	ev := osEvidence{
		guess:      "未知",
		confidence: "low",
		method:     "启发式推测",
		hints:      make([]string, 0),
	}

	// Scoring: TTL=1, Port=2, Banner=3
	score := 0

	// 1. TTL baseline
	if ttlG != "" {
		ev.guess = ttlG
		ev.confidence = ttlC
		score += 1
		ev.method = fmt.Sprintf("TTL(%d)", ttl)
		ev.hints = append(ev.hints, fmt.Sprintf("TTL 推断: %s (%s)", ttlG, ttlC))
	}

	// 2. Port combination (medium strength)
	if portG != "" {
		if score == 0 {
			ev.guess = portG
			ev.confidence = portC
		} else {
			// Check agreement
			prevWin := strings.Contains(strings.ToLower(ev.guess), "windows")
			prevLin := strings.Contains(strings.ToLower(ev.guess), "linux")
			curWin := strings.Contains(strings.ToLower(portG), "windows")
			curLin := strings.Contains(strings.ToLower(portG), "linux")

			if (prevWin && curWin) || (prevLin && curLin) {
				// 一致：采用更具体的端口判断，提升置信度
				ev.confidence = upgradeConfidence(ev.confidence, "high")
				ev.guess = portG // portG 比 TTL 猜测更具体
				ev.hints = append(ev.hints, fmt.Sprintf("端口组合确认: %s", portG))
			} else {
				// Disagree: port override (more specific)
				ev.guess = portG
				ev.confidence = portC
			}
		}
		score += 2
		if ev.method != "启发式推测" {
			ev.method += "+端口组合"
		} else {
			ev.method = "端口组合"
		}
		ev.hints = append(ev.hints, fmt.Sprintf("端口推断: %s (%s)", portG, portC))
	}

	// 3. Banner (strongest signal)
	if banG != "" {
		if score == 0 {
			ev.guess = banG
			ev.confidence = banC
		} else {
			// Check agreement with previous evidence
			prevWin := strings.Contains(strings.ToLower(ev.guess), "windows")
			prevLin := strings.Contains(strings.ToLower(ev.guess), "linux")
			curWin := strings.Contains(strings.ToLower(banG), "windows")
			curLin := strings.Contains(strings.ToLower(banG), "linux")

			if (prevWin && curWin) || (prevLin && curLin) {
				// 一致：置信度拉高，保留更具体的 Banner 判断
				ev.confidence = "high"
				ev.guess = banG // banner 最具体，直接采用
				ev.hints = append(ev.hints, fmt.Sprintf("Banner 确认: %s", banG))
			} else {
				// Disagree: Banner wins (most specific), UNLESS
				// Banner is "Linux (SSH Banner)" and we have strong Windows evidence
				if curLin && prevWin && score >= 3 {
					// SSH banner on a Windows-looking host: keep Windows, downgrade confidence
					ev.confidence = "medium"
					ev.hints = append(ev.hints, "注意: SSH Banner 与 Windows 端口特征不符，可能为 OpenSSH on Windows")
				} else {
					ev.guess = banG
				}
			}
		}
		score += 3
		if !strings.Contains(ev.method, "Banner") {
			ev.method += "+Banner"
		}
		ev.hints = append(ev.hints, fmt.Sprintf("Banner 识别: %s (%s)", banG, banC))
	}

	// Fallback
	if ev.guess == "未知" && score > 0 {
		ev.guess = "无法确定操作系统类型"
	}

	return ev
}

// upgradeConfidence returns the higher of two confidence levels.
func upgradeConfidence(current, target string) string {
	if current == "high" {
		return "high"
	}
	if target == "high" {
		return "high"
	}
	if current == "medium" && target == "medium" {
		return "high" // both medium → high
	}
	return current
}

// portsMatch checks if enough targetPorts are present in openPorts.
// ratio is the minimum fraction (0.0-1.0) of targetPorts required.
func portsMatch(opens, targets []int, ratio float64) bool {
	if len(targets) == 0 {
		return false
	}
	matches := countMatches(opens, targets)
	required := float64(len(targets)) * ratio
	return float64(matches) >= required
}

// countMatches counts how many targets are present in opens.
func countMatches(opens, targets []int) int {
	count := 0
	openSet := make(map[int]bool, len(opens))
	for _, p := range opens {
		openSet[p] = true
	}
	for _, t := range targets {
		if openSet[t] {
			count++
		}
	}
	return count
}
