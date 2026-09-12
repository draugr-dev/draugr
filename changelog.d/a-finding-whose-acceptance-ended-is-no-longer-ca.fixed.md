**A finding whose acceptance ended is no longer called "reopened".** The word is issue-tracker vocabulary for something that was fixed and came back; nothing here was ever fixed. It is `unaccepted`, named for the decision that ended rather than for a regression that did not happen. `pkg/diff.Result.Reopened` is `Unaccepted`.

**A diff ranks a critical nobody scored above a high that was scored.** The listing ordered on the CVSS score behind a severity, and not every scanner publishes one, so a finding raised to critical by an exploitation catalog sank beneath every scored high. Severity decides first now, and the score refines it where both have one, which is what the scan report already did.

**A diff whose only change is an acceptance keeps its component column.** Which component a finding belongs to was decided from the new and fixed findings alone, so a change that only accepted or un-accepted something lost the column that answers whether the finding is yours.
