package engine

import "sync"

// sfGroup collapses concurrent (and later) calls with the same key to a single execution,
// sharing its result. It is scoped to one run: entries live for the run's lifetime so any
// identical job — concurrent or subsequent — reuses the first result. A minimal in-tree
// singleflight so the engine takes no external dependency for this.
type sfGroup struct {
	mu sync.Mutex
	m  map[string]*sfCall
}

type sfCall struct {
	wg  sync.WaitGroup
	val any
	err error
}

// do runs fn for key once; concurrent/later callers with the same key wait for and share the
// result. shared is false for the caller that actually ran fn, true for those that reused it.
func (g *sfGroup) do(key string, fn func() (any, error)) (val any, shared bool, err error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*sfCall)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, true, c.err
	}
	c := &sfCall{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()
	return c.val, false, c.err
}
