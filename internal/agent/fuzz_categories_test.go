package agent

import (
	"testing"
)

// TestMinFuzzCategories_Count は MinFuzzCategories が正確に6カテゴリであることを検証する
func TestMinFuzzCategories_Count(t *testing.T) {
	t.Helper()

	want := 6
	got := len(MinFuzzCategories)
	if got != want {
		t.Errorf("MinFuzzCategories count = %d, want %d", got, want)
	}
}

// TestMinFuzzCategories_UniqueNames は全カテゴリ名がユニークであることを検証する
func TestMinFuzzCategories_UniqueNames(t *testing.T) {
	t.Helper()

	seen := make(map[string]bool)
	for _, c := range MinFuzzCategories {
		if seen[c.Name] {
			t.Errorf("duplicate category name: %q", c.Name)
		}
		seen[c.Name] = true
	}
}

// TestMinFuzzCategories_RequiredCategories は必須カテゴリが全て含まれていることを検証する
func TestMinFuzzCategories_RequiredCategories(t *testing.T) {
	t.Helper()

	required := []string{"sqli", "path", "ssti", "cmdi", "xss_probe", "numeric"}

	names := make(map[string]bool)
	for _, c := range MinFuzzCategories {
		names[c.Name] = true
	}

	for _, r := range required {
		if !names[r] {
			t.Errorf("required category %q not found in MinFuzzCategories", r)
		}
	}
}

// TestFuzzCategoryNames は FuzzCategoryNames() が正しい名前リストを返すことを検証する
func TestFuzzCategoryNames(t *testing.T) {
	t.Helper()

	got := FuzzCategoryNames()

	if len(got) != len(MinFuzzCategories) {
		t.Fatalf("FuzzCategoryNames() returned %d names, want %d", len(got), len(MinFuzzCategories))
	}

	for i, c := range MinFuzzCategories {
		if got[i] != c.Name {
			t.Errorf("FuzzCategoryNames()[%d] = %q, want %q", i, got[i], c.Name)
		}
	}
}

// TestMinFuzzCategories_NonEmpty は全カテゴリの Name と Description が空でないことを検証する
func TestMinFuzzCategories_NonEmpty(t *testing.T) {
	t.Helper()

	for i, c := range MinFuzzCategories {
		if c.Name == "" {
			t.Errorf("MinFuzzCategories[%d].Name is empty", i)
		}
		if c.Description == "" {
			t.Errorf("MinFuzzCategories[%d].Description is empty", i)
		}
	}
}
