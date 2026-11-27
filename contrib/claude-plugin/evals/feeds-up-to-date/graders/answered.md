---
type: llm
focus: trace
---

Find the result feeds_status returned in the trace. It lists the feeds kev, epss and govulndb, each
with `cached` and `stale`, and a `next` command when any feed is missing or stale.

PASS if the final reply does all three:

1. Says, for each of the three feeds or for all of them together, whether it is cached and current,
   stale, or missing, and what it says agrees with the feeds_status result.
2. When the result has a `next` command, gives that command for the user to run. When it has none,
   says nothing needs refreshing.
3. Says how old the data is, by age or by the time it was fetched, for at least one cached feed, or
   says no feed is cached.

FAIL if the reply contradicts the feeds_status result about any feed, or says the agent refreshed
or downloaded a feed itself.
