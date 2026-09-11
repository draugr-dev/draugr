- `config.gate.controls` no longer needs `config.gate.failOn` written above it. A descriptor that
  set per-control thresholds and left the gate on the default was refused with "there is none to
  refine", when the default gate is `P1` and there was one. A severity under that default band is
  still refused, and now says the default moved rather than that the gate does not exist.
