package agent

// FuzzCategory はバリューファジングのカテゴリ
type FuzzCategory struct {
	Name        string // カテゴリ識別子 (e.g. "sqli")
	Description string // SubAgent プロンプト用の説明
}

// MinFuzzCategories は必須ファジングカテゴリ（SubAgent は全カテゴリを必ずテストする）
var MinFuzzCategories = []FuzzCategory{
	{Name: "numeric", Description: "IDOR/privilege escalation: sequential IDs (0, 1, 2, -1, 99999)"},
	{Name: "sqli", Description: "SQL Injection: quotes, comments, boolean logic"},
	{Name: "path", Description: "Path Traversal: ../ sequences, encoding variants"},
	{Name: "ssti", Description: "Template Injection: {{7*7}}, ${7*7}, #{7*7}"},
	{Name: "cmdi", Description: "Command Injection: ;id, |id, `id`, $(id)"},
	{Name: "xss_probe", Description: "XSS: script tags, event handlers, javascript: URI"},
}

// FuzzCategoryNames は MinFuzzCategories の名前リストを返す（プロンプト注入用）
func FuzzCategoryNames() []string {
	names := make([]string, len(MinFuzzCategories))
	for i, c := range MinFuzzCategories {
		names[i] = c.Name
	}
	return names
}
