package models

import (
	"fmt"
	"net"
	"sort"
)

// RiskLevel 端口风险等级
type RiskLevel string

const (
	RiskCritical RiskLevel = "Critical"
	RiskHigh     RiskLevel = "High"
	RiskMedium   RiskLevel = "Medium"
	RiskLow      RiskLevel = "Low"
)

// PortInfo 单个端口信息
type PortInfo struct {
	Port    int       `json:"port"`
	Service string    `json:"service"`
	Risk    RiskLevel `json:"risk"`
	Banner  string    `json:"banner,omitempty"`
	IsOpen  bool      `json:"is_open"`
}

// OSGuess 操作系统推断
type OSGuess struct {
	Guess      string   `json:"guess"`
	Confidence string   `json:"confidence"` // high / medium / low
	Method     string   `json:"method"`     // 推断方法 (e.g., "Banner+端口组合")
	TTLValue   int      `json:"ttl_value,omitempty"`
	Hints      []string `json:"hints,omitempty"`
}

// RoleGuess 角色推断
type RoleGuess struct {
	Role         string  `json:"role"`
	Confidence   float64 `json:"confidence"` // 0.0 - 1.0
	MatchedPorts []int   `json:"matched_ports"`
	Desc         string  `json:"desc"`
	OSHint       string  `json:"os_hint,omitempty"`
}

// AttackSuggestion 攻击建议
type AttackSuggestion struct {
	Service   string `json:"service"`
	Priority  int    `json:"priority"` // 1=最高
	Tool      string `json:"tool"`     // impacket / msf / evil-winrm / rdesktop / ldapsearch
	Command   string `json:"command"`
	Condition string `json:"condition"` // 执行条件，如"有凭证"
	Explain   string `json:"explain"`   // 教学解释
}

// Host 单台主机的完整信息
type Host struct {
	IP          string             `json:"ip"`
	Hostname    string             `json:"hostname,omitempty"`
	IsAlive     bool               `json:"is_alive"`
	TTL         int                `json:"ttl,omitempty"`
	OS          OSGuess            `json:"os,omitempty"`
	Roles       []RoleGuess        `json:"roles,omitempty"`
	Ports       []PortInfo         `json:"ports,omitempty"`
	Suggestions []AttackSuggestion `json:"suggestions,omitempty"`
}

// ScanResult 整体扫描结果
type ScanResult struct {
	Targets    string `json:"targets"`
	Hosts      []Host `json:"hosts"`
	AliveCount int    `json:"alive_count"`
	TotalPorts int    `json:"total_ports"` // 开放端口总数
}

// GetOpenPorts 返回所有开放端口
func (h *Host) GetOpenPorts() []PortInfo {
	var result []PortInfo
	for _, p := range h.Ports {
		if p.IsOpen {
			result = append(result, p)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Port < result[j].Port
	})
	return result
}

// HasPort 检查主机是否开放了指定端口
func (h *Host) HasPort(port int) bool {
	for _, p := range h.Ports {
		if p.Port == port && p.IsOpen {
			return true
		}
	}
	return false
}

// HasAllPorts 检查主机是否开放了所有指定端口
func (h *Host) HasAllPorts(ports []int) bool {
	for _, port := range ports {
		if !h.HasPort(port) {
			return false
		}
	}
	return true
}

// HasAnyPort 检查主机是否开放了任意一个指定端口
func (h *Host) HasAnyPort(ports []int) bool {
	for _, port := range ports {
		if h.HasPort(port) {
			return true
		}
	}
	return false
}

// String 返回主机的简要描述
func (h *Host) String() string {
	if h.Hostname != "" {
		return fmt.Sprintf("%s (%s)", h.IP, h.Hostname)
	}
	return h.IP
}

// CIDRToIPs 将 CIDR 转换为 IP 列表
func CIDRToIPs(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// 去掉网络地址和广播地址
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
