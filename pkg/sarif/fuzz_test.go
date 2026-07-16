package sarif

import "testing"

// FuzzFromSARIF exercises the SARIF parser against arbitrary input: it must return an error,
// never panic, on malformed or hostile SARIF documents.
func FuzzFromSARIF(f *testing.F) {
	f.Add([]byte(`{"runs":[]}`))
	f.Add([]byte(`{"runs":[{"tool":{"driver":{"name":"Draugr"}},"results":[{"ruleId":"X","level":"error"}]}]}`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = FromSARIF(data) // must not panic
	})
}
