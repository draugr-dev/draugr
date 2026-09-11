- A publisher says what it is given. `config.publishers[].reports` narrows a destination to the
  formats it is for, so writing HTML and JSON to a directory while posting a short markdown
  summary to a pull request is now expressible: it was three formats handed to every destination,
  each picking out what it recognized. `minPriority` and `filename` go under the destination that
  needs them. `config.reports` still names the set every destination that does not narrow is
  given, and is what `-o` writes with no publisher involved, so nothing that worked before
  changes. Each distinct report is still rendered once, however many destinations ask for it.
