package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// DefaultTCPProbePorts 用于 TCP 存活探测的常见端口
// 选择内网中通常开放的高概率端口（Windows: 445/135/3389, Linux: 22/80）
var DefaultTCPProbePorts = []int{445, 135, 139, 80, 22, 3389, 5985}

// CheckAliveTCP 通过 TCP Connect 检测主机是否存活
// 并发尝试常见端口，任一成功即返回 true（通过 context 取消其他探测）
func CheckAliveTCP(ip string, timeout time.Duration) bool {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultCh := make(chan bool, 1)
	var wg sync.WaitGroup

	for _, port := range DefaultTCPProbePorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			// 检查是否已取消（另一个端口已成功）
			select {
			case <-ctx.Done():
				return
			default:
			}

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, p), timeout)
			if err != nil {
				return
			}
			conn.Close()

			// 成功，通知其他 goroutine 停止
			cancel()
			select {
			case resultCh <- true:
			default:
			}
		}(port)
	}

	// 等待第一个结果或所有探测失败
	go func() {
		wg.Wait()
		select {
		case resultCh <- false:
		default:
		}
	}()

	return <-resultCh
}

// CheckAlives 批量检测主机存活（并发控制）
// 返回存活 IP 列表
func CheckAlives(ips []string, timeout time.Duration, threads int) []string {
	var result []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads) // 并发控制信号量

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}        // 获取信号量
			defer func() { <-sem }() // 释放信号量

			if CheckAliveTCP(ip, timeout) {
				mu.Lock()
				result = append(result, ip)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return result
}
