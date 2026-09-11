- A cached scan result now names the commit it describes. A repository that declares no revision,
  which is what `url: .` and most descriptors write, had one cache identity for its whole life, so
  an entry outlived the commit it was computed from and the next run at any commit was served the
  previous one's findings. The visible direction was a stale failure; the quiet one was a clean
  answer about a commit that had just introduced a vulnerable dependency. Draugr resolves the
  revision to a commit before building the key, and a repository whose revision cannot be resolved
  is scanned and not cached rather than stored under a name that moves.
