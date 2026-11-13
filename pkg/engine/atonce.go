package engine

// unfinishedJobs counts a run's jobs not yet finished, to say how many can run at once. Not safe
// for concurrent use; the run holds its lock around every call.
type unfinishedJobs struct {
	// exclusive is the resource each scanner takes whole, for the scanners that take one.
	exclusive map[string]string
	// free counts the unfinished jobs of scanners that take no resource whole.
	free int
	// turns counts the unfinished jobs taking turns at each resource.
	turns map[string]int
}

func newUnfinishedJobs(reg *Registry, planned []PlannedJob) *unfinishedJobs {
	u := &unfinishedJobs{exclusive: map[string]string{}, turns: map[string]int{}}
	for _, pj := range planned {
		if sc, ok := reg.Scanner(pj.Job.Scanner); ok && sc.Info().Exclusive != "" {
			u.exclusive[pj.Job.Scanner] = sc.Info().Exclusive
		}
		u.add(pj.Job.Scanner, 1)
	}
	return u
}

func (u *unfinishedJobs) add(scanner string, n int) {
	if res, ok := u.exclusive[scanner]; ok {
		u.turns[res] += n
		return
	}
	u.free += n
}

// finish records that one of scanner's jobs has ended.
func (u *unfinishedJobs) finish(scanner string) { u.add(scanner, -1) }

// atOnce is how many of the unfinished jobs can run at the same moment: every job of a scanner that
// takes no resource whole, and one for each resource some unfinished jobs take turns at.
func (u *unfinishedJobs) atOnce() int {
	n := u.free
	for _, waiting := range u.turns {
		if waiting > 0 {
			n++
		}
	}
	return n
}
