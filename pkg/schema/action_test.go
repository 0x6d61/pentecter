package schema

import (
	"encoding/json"
	"testing"
)

// TestActionSearchKnowledge_MarshalJSON は search_knowledge アクションの JSON マーシャリングをテストする。
func TestActionSearchKnowledge_MarshalJSON(t *testing.T) {
	action := Action{
		Thought:        "Need to look up vsftpd 2.3.4 exploit techniques",
		Action:         ActionSearchKnowledge,
		KnowledgeQuery: "vsftpd 2.3.4 exploit",
	}

	data, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}

	if got["action"] != string(ActionSearchKnowledge) {
		t.Errorf("action = %v, want %v", got["action"], ActionSearchKnowledge)
	}
	if got["knowledge_query"] != "vsftpd 2.3.4 exploit" {
		t.Errorf("knowledge_query = %v, want %v", got["knowledge_query"], "vsftpd 2.3.4 exploit")
	}
	// command フィールドは omitempty なので含まれないこと
	if _, ok := got["command"]; ok {
		t.Errorf("command field should not be present for search_knowledge action")
	}
	// knowledge_path フィールドは omitempty なので含まれないこと
	if _, ok := got["knowledge_path"]; ok {
		t.Errorf("knowledge_path field should not be present for search_knowledge action")
	}
}

// TestActionSearchKnowledge_UnmarshalJSON は search_knowledge アクションの JSON アンマーシャリングをテストする。
func TestActionSearchKnowledge_UnmarshalJSON(t *testing.T) {
	raw := `{
		"thought": "Looking up SQL injection techniques",
		"action": "search_knowledge",
		"knowledge_query": "sql injection union based"
	}`

	var action Action
	if err := json.Unmarshal([]byte(raw), &action); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if action.Action != ActionSearchKnowledge {
		t.Errorf("Action = %v, want %v", action.Action, ActionSearchKnowledge)
	}
	if action.KnowledgeQuery != "sql injection union based" {
		t.Errorf("KnowledgeQuery = %v, want %v", action.KnowledgeQuery, "sql injection union based")
	}
	if action.Thought != "Looking up SQL injection techniques" {
		t.Errorf("Thought = %v, want %v", action.Thought, "Looking up SQL injection techniques")
	}
	// 未設定フィールドはゼロ値であること
	if action.KnowledgePath != "" {
		t.Errorf("KnowledgePath should be empty, got %v", action.KnowledgePath)
	}
	if action.Command != "" {
		t.Errorf("Command should be empty, got %v", action.Command)
	}
}

// TestActionReadKnowledge_MarshalJSON は read_knowledge アクションの JSON マーシャリングをテストする。
func TestActionReadKnowledge_MarshalJSON(t *testing.T) {
	action := Action{
		Thought:       "Reading detailed exploit instructions for vsftpd",
		Action:        ActionReadKnowledge,
		KnowledgePath: "network-services-pentesting/pentesting-ftp/ftp-bounce-attack.md",
	}

	data, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}

	if got["action"] != string(ActionReadKnowledge) {
		t.Errorf("action = %v, want %v", got["action"], ActionReadKnowledge)
	}
	if got["knowledge_path"] != "network-services-pentesting/pentesting-ftp/ftp-bounce-attack.md" {
		t.Errorf("knowledge_path = %v, want expected path", got["knowledge_path"])
	}
	// command フィールドは omitempty なので含まれないこと
	if _, ok := got["command"]; ok {
		t.Errorf("command field should not be present for read_knowledge action")
	}
	// knowledge_query フィールドは omitempty なので含まれないこと
	if _, ok := got["knowledge_query"]; ok {
		t.Errorf("knowledge_query field should not be present for read_knowledge action")
	}
}

// TestActionReadKnowledge_UnmarshalJSON は read_knowledge アクションの JSON アンマーシャリングをテストする。
func TestActionReadKnowledge_UnmarshalJSON(t *testing.T) {
	raw := `{
		"thought": "Reading privilege escalation guide",
		"action": "read_knowledge",
		"knowledge_path": "linux-hardening/privilege-escalation/README.md"
	}`

	var action Action
	if err := json.Unmarshal([]byte(raw), &action); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if action.Action != ActionReadKnowledge {
		t.Errorf("Action = %v, want %v", action.Action, ActionReadKnowledge)
	}
	if action.KnowledgePath != "linux-hardening/privilege-escalation/README.md" {
		t.Errorf("KnowledgePath = %v, want expected path", action.KnowledgePath)
	}
	if action.Thought != "Reading privilege escalation guide" {
		t.Errorf("Thought = %v, want expected value", action.Thought)
	}
	// 未設定フィールドはゼロ値であること
	if action.KnowledgeQuery != "" {
		t.Errorf("KnowledgeQuery should be empty, got %v", action.KnowledgeQuery)
	}
	if action.Command != "" {
		t.Errorf("Command should be empty, got %v", action.Command)
	}
}

// TestActionKnowledge_RoundTrip は Knowledge アクションの JSON ラウンドトリップをテストする。
func TestActionKnowledge_RoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		action Action
	}{
		{
			name: "search_knowledge round trip",
			action: Action{
				Thought:        "Searching for privilege escalation techniques",
				Action:         ActionSearchKnowledge,
				KnowledgeQuery: "privilege escalation linux",
			},
		},
		{
			name: "read_knowledge round trip",
			action: Action{
				Thought:       "Reading detailed article",
				Action:        ActionReadKnowledge,
				KnowledgePath: "pentesting-web/sql-injection/README.md",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.action)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			var got Action
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			if got.Thought != tt.action.Thought {
				t.Errorf("Thought = %v, want %v", got.Thought, tt.action.Thought)
			}
			if got.Action != tt.action.Action {
				t.Errorf("Action = %v, want %v", got.Action, tt.action.Action)
			}
			if got.KnowledgeQuery != tt.action.KnowledgeQuery {
				t.Errorf("KnowledgeQuery = %v, want %v", got.KnowledgeQuery, tt.action.KnowledgeQuery)
			}
			if got.KnowledgePath != tt.action.KnowledgePath {
				t.Errorf("KnowledgePath = %v, want %v", got.KnowledgePath, tt.action.KnowledgePath)
			}
		})
	}
}
