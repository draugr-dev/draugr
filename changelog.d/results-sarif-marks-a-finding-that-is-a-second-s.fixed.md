- `results.sarif` marks a finding that is a second scanner's copy of a flaw already counted, with
  `properties.correlation.countedUnder`, and the counted one carries `alsoFoundBy` with each other
  tool's own rule id and rating. Nothing in the file said which was which, so GitHub code scanning
  opened eighteen alerts for nine vulnerabilities and dismissing one left its twin open under the
  other tool's rule id. `draugr diff`'s gate now skips the copies too: a pull request should not
  fail over findings that arrived because somebody enabled a second matcher.
