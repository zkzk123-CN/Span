// Package output provides terminal and file output formatting for Span scan results.
package output

import (
	"fmt"
	"strings"

	"github.com/span-dev/span/internal/rules"
)

// getPortDescFromRules 从规则库获取端口说明（统一数据源，避免重复）
func getPortDescFromRules(port int) string {
	if rule := rules.GetPortRule(port); rule != nil {
		return rule.Desc
	}
	return "未知服务"
}

// formatIntSlice 将整数切片格式化为 "22, 80, 443" 字符串
func formatIntSlice(nums []int) string {
	if len(nums) == 0 {
		return ""
	}
	result := fmt.Sprintf("%d", nums[0])
	for i := 1; i < len(nums); i++ {
		result += fmt.Sprintf(", %d", nums[i])
	}
	return result
}

// StripANSICodes 去除字符串中的 ANSI 颜色码
func StripANSICodes(s string) string {
	// 简单的去除方法：删除 \033[...m 模式
	result := strings.Builder{}
	inEscape := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if s[i] == 'm' {
				inEscape = false
			}
			continue
		}
		result.WriteByte(s[i])
	}
	return result.String()
}
