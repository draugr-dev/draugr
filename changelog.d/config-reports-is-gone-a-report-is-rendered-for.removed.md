- `config.reports` is gone. A report is rendered for a destination, so it is named on the
  destination that takes it: move each entry under the `config.publishers` entry it was for, which
  is also where `filename` and `minPriority` now mean something. A descriptor still carrying it is
  refused, with that sentence. For local artifacts and no destination at all, `-o <dir>` writes
  `report.json` and `results.sarif` and `--report <format>` adds to them, which is what the key
  never did.
