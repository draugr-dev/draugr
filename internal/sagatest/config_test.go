package sagatest

import "testing"

func TestConfigSchemaErrorJudgesAConfigFile(t *testing.T) {
	ok := map[string]any{"output": map[string]any{"view": "actions"}}
	if err := ConfigSchemaError(t, ok); err != nil {
		t.Errorf("a valid config file is refused: %v", err)
	}
	bad := map[string]any{"output": map[string]any{"veiw": "actions"}}
	if err := ConfigSchemaError(t, bad); err == nil {
		t.Error("an unknown key under output is accepted")
	}
}
