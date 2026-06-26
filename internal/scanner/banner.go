package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// GrabBanner 尝试读取服务的 Banner 信息
// 连接端口后读取前 1024 字节，尝试解析为字符串
// Phase 1 简化实现，复杂协议（如 SMB）留到 Phase 2
func GrabBanner(ip string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(timeout))

	// 对于某些协议，需要先发送数据才能收到 Banner
	// 这里先发送一个通用探针（\n 或空行）
	switch port {
	case 21: // FTP
		// FTP 会主动发送 Banner，不需要发送数据
	case 22: // SSH
		// SSH 会主动发送 Banner
	case 25, 587: // SMTP/Submission
		// SMTP 会主动发送 Banner
	case 110: // POP3
		// POP3 会主动发送 Banner
	case 143: // IMAP
		// IMAP 会主动发送 Banner
	default:
		// 对于其他协议，尝试发送一个换行（可能触发 Banner）
		conn.SetWriteDeadline(time.Now().Add(timeout))
		conn.Write([]byte("\n"))
	}

	// 读取 Banner
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}

	banner := strings.TrimSpace(string(buf[:n]))

	// 清理不可打印字符
	banner = cleanString(banner)

	// 限制长度
	if len(banner) > 200 {
		banner = banner[:200] + "..."
	}

	return banner
}

// cleanString 清理字符串中的不可打印字符
func cleanString(s string) string {
	var result []rune
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			result = append(result, ' ')
		} else if r < 32 || r == 127 {
			// 跳过不可打印字符
			continue
		} else {
			result = append(result, r)
		}
	}
	return strings.TrimSpace(string(result))
}

// GrabBanners 批量抓取 Banner（并发）
func GrabBanners(ip string, ports []int, timeout time.Duration, threads int) map[int]string {
	results := make(map[int]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			banner := GrabBanner(ip, p, timeout)
			if banner != "" {
				mu.Lock()
				results[p] = banner
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return results
}
