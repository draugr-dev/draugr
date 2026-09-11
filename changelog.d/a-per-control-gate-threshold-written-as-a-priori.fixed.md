- A per-control gate threshold written as a priority band now decides something.
  `config.gate.controls` has taken a band since the gate took one, and every band was parsed as a
  severity, failed, and dropped, so the whole per-control block did nothing on a band gate, which
  is the default. A control held to `P2` under a `P1` gate now fails on a P2, the console says
  `fails on P1, except licenses on P2`, and `report.json` records what was applied rather than
  what was written.
