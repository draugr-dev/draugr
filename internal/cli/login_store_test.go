package cli

import (
	"os"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/login"
)

// TestMain gives every test an empty login store in place of the OS keychain, and a machine that is
// not a CI job, so no test reads or writes the keychain of the machine running it and the policy
// check answers the same on a laptop and on a runner.
func TestMain(m *testing.M) {
	loginStore = func() login.Store { return &memoryLogins{} }
	inPipeline = func() bool { return false }
	os.Exit(m.Run())
}

// memoryLogins is a login.Store in memory, counting its reads.
type memoryLogins struct {
	mu     sync.Mutex
	held   map[string]login.Login
	reads  int
	setErr error
	getErr error
}

func (m *memoryLogins) Get(origin string) (login.Login, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	if m.getErr != nil {
		return login.Login{}, m.getErr
	}
	l, ok := m.held[origin]
	if !ok {
		return login.Login{}, login.ErrNotLoggedIn
	}
	return l, nil
}

func (m *memoryLogins) Set(origin string, l login.Login) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.setErr != nil {
		return m.setErr
	}
	if m.held == nil {
		m.held = map[string]login.Login{}
	}
	m.held[origin] = l
	return nil
}

func (m *memoryLogins) Delete(origin string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.held[origin]; !ok {
		return login.ErrNotLoggedIn
	}
	delete(m.held, origin)
	return nil
}

// useLogins puts store in place of the keychain for one test.
func useLogins(t *testing.T, store *memoryLogins) {
	t.Helper()
	prev := loginStore
	loginStore = func() login.Store { return store }
	t.Cleanup(func() { loginStore = prev })
}
