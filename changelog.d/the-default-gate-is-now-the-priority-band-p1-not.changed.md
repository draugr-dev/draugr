- **The default gate is now the priority band `P1`, not `high` severity.** Severity rates a flaw
  in the abstract; priority folds in the exposure and criticality your descriptor declares, which
  is context no scanner can compute, and it is the ranking Draugr exists to produce. On a
  component that declares nothing, `P1` catches exactly what `--fail-on high` caught. On a
  component you have classified, the gate now follows what you said about it.
