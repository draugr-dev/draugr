package saga

import "testing"

// FuzzLoad exercises the Saga parser (YAML + env substitution + validation) against arbitrary
// input: it must return an error, never panic, on malformed descriptors.
func FuzzLoad(f *testing.F) {
	f.Add([]byte("release:\n  version: '1'\n"))
	f.Add([]byte("release:\n  version: '1'\ncomponents:\n  - name: a\n    images:\n     - image: alpine:3.19\n"))
	f.Add([]byte("components:\n  - name: a\n    exposure: public\n"))
	f.Add([]byte("not: [valid"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = Load(data) // must not panic
	})
}
