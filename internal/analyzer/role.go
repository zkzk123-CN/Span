package analyzer

import (
	"fmt"
	"sort"

	"github.com/span-dev/span/internal/rules"
	"github.com/span-dev/span/pkg/models"
)

// AnalyzeRole infers the host's role based on open port combinations.
// Returns a list of possible roles sorted by confidence (best match first).
func AnalyzeRole(ports []models.PortInfo) []models.RoleGuess {
	if len(ports) == 0 {
		return []models.RoleGuess{
			{
				Role:         "未知",
				Confidence:   0,
				MatchedPorts: []int{},
				Desc:         "未检测到开放端口",
			},
		}
	}

	openPortNums := make([]int, 0, len(ports))
	for _, p := range ports {
		openPortNums = append(openPortNums, p.Port)
	}

	roleRules := rules.DefaultRoleRules()
	candidates := make([]roleCandidate, 0, len(roleRules))

	for _, rule := range roleRules {
		score, matchedPorts := scoreRoleRule(rule, openPortNums)
		if score > 0 {
			confidence := calculateConfidence(score, rule)
			candidates = append(candidates, roleCandidate{
				rule:         rule,
				score:        score,
				matchedPorts: matchedPorts,
				confidence:   confidence,
			})
		}
	}

	// Sort by score (desc), then by weight (desc)
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].rule.Weight > candidates[j].rule.Weight
	})

	// Convert to output format (top 3 matches max)
	result := make([]models.RoleGuess, 0, min(3, len(candidates)))
	for i, c := range candidates {
		if i >= 3 {
			break
		}
		desc := c.rule.Desc
		if c.score < fullScore(c.rule) {
			desc += fmt.Sprintf(" (部分匹配: %d/%d required)", countMatchRequired(c), len(c.rule.Required))
		}

		result = append(result, models.RoleGuess{
			Role:         c.rule.Name,
			Confidence:   c.confidence,
			MatchedPorts: c.matchedPorts,
			Desc:         desc,
			OSHint:       c.rule.OSHint,
		})
	}

	if len(result) == 0 {
		return []models.RoleGuess{
			{
				Role:         "通用主机",
				Confidence:   0.2,
				MatchedPorts: openPortNums,
				Desc:         "开放端口不匹配任何已知角色模式，需人工分析",
				OSHint:       "未知",
			},
		}
	}

	return result
}

type roleCandidate struct {
	rule         rules.RoleRule
	score        float64 // 0-1 normalized
	matchedPorts []int
	confidence   float64 // 0-1
}

// scoreRoleRule calculates how well open ports match a role rule.
// Returns score (0-1) and which ports contributed to the match.
func scoreRoleRule(rule rules.RoleRule, openPorts []int) (float64, []int) {
	openSet := make(map[int]bool, len(openPorts))
	for _, p := range openPorts {
		openSet[p] = true
	}

	matchedPorts := make([]int, 0)
	requiredHits := 0

	// All required ports must be present for any positive score
	allRequiredMet := true
	for _, rp := range rule.Required {
		if openSet[rp] {
			requiredHits++
			matchedPorts = append(matchedPorts, rp)
		} else {
			allRequiredMet = false
		}
	}

	if !allRequiredMet || requiredHits == 0 {
		return 0, nil
	}

	// Bonus for optional ports
	optHits := 0
	for _, op := range rule.Optional {
		if openSet[op] {
			optHits++
			matchedPorts = append(matchedPorts, op)
		}
	}

	// Score calculation:
	// - Required ports fully matched = base 0.6
	// - Each optional port adds 0.05 (up to 0.35 total from optional)
	// - Weight bonus (higher weight = slightly higher score)
	baseScore := 0.6
	bonusPerOptional := 0.04
	maxOptionalBonus := float64(len(rule.Optional)) * bonusPerOptional
	if maxOptionalBonus > 0.35 {
		maxOptionalBonus = 0.35
	}
	optionalBonus := float64(optHits) * bonusPerOptional
	if optionalBonus > maxOptionalBonus {
		optionalBonus = maxOptionalBonus
	}

	weightFactor := 1.0 + (float64(rule.Weight)-5)*0.01 // subtle weight influence

	score := (baseScore + optionalBonus) * weightFactor
	if score > 1.0 {
		score = 1.0
	}

	return score, matchedPorts
}

func calculateConfidence(score float64, rule rules.RoleRule) float64 {
	// Start with rule's base confidence and adjust by actual score
	base := rule.Confidence
	adjustment := score * 0.2 // up to 0.2 boost
	result := base + adjustment
	if result > 0.99 {
		result = 0.99
	}
	if result < 0.1 {
		result = 0.1
	}
	return result
}

func fullScore(rule rules.RoleRule) float64 {
	return 0.6 + float64(len(rule.Optional))*0.04
}

func countMatchRequired(c roleCandidate) int {
	count := 0
	for _, mp := range c.matchedPorts {
		for _, rp := range c.rule.Required {
			if mp == rp {
				count++
				break
			}
		}
	}
	return count
}

// Note: min() is a built-in function in Go 1.21+
