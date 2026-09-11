- `draugr scan` refuses a gate the descriptor's own classifications cannot produce, instead of
  passing every run in silence. A component declared `restricted` and `important` ranks a critical
  finding `P2`, so a gate on `P1` there could never fire; the message names the classification,
  the band it does reach, and the three things you can do about it. Where only some components are
  out of reach the run says so and continues. A control that declares a priority floor keeps its
  band reachable, so enabling `secrets` on a restricted component is not reported as a dead gate.
