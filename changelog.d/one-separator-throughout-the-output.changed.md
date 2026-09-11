- **One separator throughout the output.** Reports separate a label from what follows with `·`,
  the separator the rest of the output already used, in place of an em dash: `Draugr · FAIL`, `Fix
  first · 5 actions clear 6 findings`, `↑ ranked as critical · on KEV`. Error messages read as
  sentences rather than clauses joined by a dash. Anything parsing the console text should read
  the machine formats instead.
