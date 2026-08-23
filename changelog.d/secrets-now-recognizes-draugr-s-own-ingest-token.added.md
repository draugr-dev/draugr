**`secrets` now recognizes Draugr's own ingest token.** The credential a pipeline presents to publish a run carries a fixed marker, and `draugr scan` catches one the moment it is pasted into a repository — as it would anybody else's leaked credential.

Draugr's rules **extend** whatever ruleset the scan would otherwise have used rather than replacing it, so a `gitleaks.config` you already set keeps working and gains this. Replacing yours would lose your rules; skipping ours when you have one would leave the token undetected in exactly the repositories configured most carefully.
