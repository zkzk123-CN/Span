package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/span-dev/span/internal/rules"
	"github.com/span-dev/span/pkg/models"
)

// DefaultPorts 返回默认扫描端口列表（18个横向移动相关端口）
// 数据源：rules 包中的 DefaultPortRules()
func DefaultPorts() []int {
	return rules.GetAllTargetPorts()
}

// ScanPort 扫描单个端口，返回是否开放
func ScanPort(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ScanPorts 并发扫描多个端口，返回按端口号排序的开放端口列表
// 服务名称和风险评估从 rules 包动态获取（单一数据源）
func ScanPorts(ip string, ports []int, timeout time.Duration, threads int) []models.PortInfo {
	type scanResult struct {
		port int
		open bool
	}

	results := make([]models.PortInfo, 0, len(ports))
	resultCh := make(chan scanResult, len(ports))
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	// 并发扫描
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			open := ScanPort(ip, p, timeout)
			resultCh <- scanResult{port: p, open: open}
		}(port)
	}

	// 等待所有扫描完成
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// 收集结果并填充服务信息（从 rules 包）
	for r := range resultCh {
		if r.open {
			portInfo := models.PortInfo{
				Port:   r.port,
				IsOpen: true,
			}

			// 从规则库获取端口的服务名称和风险评估
			if rule := rules.GetPortRule(r.port); rule != nil {
				portInfo.Service = rule.Service
				portInfo.Risk = rule.Risk
			} else {
				portInfo.Service = "unknown"
				portInfo.Risk = models.RiskLow
			}

			results = append(results, portInfo)
		}
	}

	// 按端口号排序
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}

// ScanHost 扫描单台主机的完整流程：存活探测 + 端口扫描
// 返回 Host 对象（如果存活但无开放端口，Host 仍会返回，Ports 为空）
func ScanHost(ip string, ports []int, timeout time.Duration, scannerThreads int) *models.Host {
	host := &models.Host{
		IP:      ip,
		IsAlive: false,
		Ports:   []models.PortInfo{},
	}

	// 存活探测
	alive := CheckAliveTCP(ip, timeout)
	if !alive {
		return host
	}
	host.IsAlive = true
	// Note: TTL 无法通过 TCP Ping 获取（需 raw socket / ICMP）
	// --analyze 模式下从 fscan/nmap 输出中提取 TTL

	// 端口扫描
	openPorts := ScanPorts(ip, ports, timeout, scannerThreads)
	host.Ports = openPorts

	return host
}

// ScanHosts 批量扫描主机（并发控制由调用方通过 CheckAlives 控制）
func ScanHosts(aliveIPs []string, ports []int, timeout time.Duration, threads int) []models.Host {
	hosts := make([]models.Host, 0, len(aliveIPs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	for _, ip := range aliveIPs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			host := ScanHost(ip, ports, timeout, threads)
			if host.IsAlive {
				mu.Lock()
				hosts = append(hosts, *host)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()

	// 按 IP 排序
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].IP < hosts[j].IP
	})

	return hosts
}
