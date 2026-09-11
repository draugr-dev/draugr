- The main example recommends the gate Draugr recommends. `examples/draugr.saga.yaml` explained
  that `P1` is the default and then set `failOn: high` on the next line, so anyone copying it got
  a severity gate and the explanation read as advice against itself. It writes `failOn: P1`, with
  the severity form named as the alternative, and its per-control thresholds are bands rather than
  severities under a band gate, which is a pairing Draugr refuses.
