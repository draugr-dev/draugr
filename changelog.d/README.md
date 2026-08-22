# Unreleased entries

One file per change. The release assembles them into `CHANGELOG.md`.

```bash
printf -- '- **What you can now do.** And why it matters.\n' | ./scripts/changelog.sh add added
```

That writes `changelog.d/what-you-can-now-do.added.md`. Name it yourself with a third argument
when the derived name is unhelpful.

**A file per change rather than a line in `CHANGELOG.md`.** Every open pull request would otherwise
edit the same few lines of the same file: two of them conflict, and resolving that by hand is how a
section ends up out of order, or how somebody drops the other change while fixing their own.
Nothing here can collide with anything.

## The rules

- **The name ends `.<section>.md`** — one of `added`, `changed`, `deprecated`, `removed`, `fixed`,
  `security`. `changelog.sh check` refuses anything else, because a fragment that matches no
  section sits here looking queued and ships in no release at all.
- **The content is the entry**, exactly as it should read in the notes: a `-` bullet, user-first —
  what you can now do, not which functions moved.
- **Fragments assemble in filename order** within a section, so two people writing on the same
  afternoon get the same notes whichever order their pull requests merged.

Everything here is cleared by `changelog.sh promote`, which the release workflow runs. A fragment
that survived its own release would ship twice, in two releases, with nothing to say which was
meant.
