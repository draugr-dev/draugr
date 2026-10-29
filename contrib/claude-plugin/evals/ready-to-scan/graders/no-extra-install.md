---
type: regex
target: trace
pattern: 'tools install[^"\n]*\b(gosec|syft)\b'
match: not_contains
arm: with-only
---
