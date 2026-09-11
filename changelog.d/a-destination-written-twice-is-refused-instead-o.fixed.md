- A destination written twice is refused instead of delivering twice. `config.publishers` is a
  list and two entries of one kind may be deliberate, two directories or two servers, or a
  mistake, and the two were written identically. Draugr now refuses a pair that does not differ in
  the field which makes it a second destination, naming that field, which is `dir` for `file`,
  `url` for `draugr-api`, `repo` for `github` and the sticky comment's `marker` for the rest.
