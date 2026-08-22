- **The reference now documents the `draugr-api` publisher again.** Its section in the Saga
  schema reference went missing in 0.104.0; the publisher itself, its JSON schema entry and the
  how-to guide were unaffected, so a descriptor using it always worked. A test now checks every
  registered publisher appears in the catalog, the guide and the schema reference, because a
  publisher missing from any one of them is invisible to whoever started there.

  The reference also states where a setting comes from, least specific first:
  `~/.draugr/config.yaml` → `./draugr.config.yaml` → `$DRAUGR_API_URL` → `url:` in the Saga.
  Explicit wins: an environment variable is context, and a `url:` somebody wrote is intent.
