- **One endpoint for the whole organization.** `draugr.config.yaml` gained a `publish.apiUrl`
  field, so forty repositories pointing at one install no longer repeat the endpoint in forty
  descriptors — set it once in a runner image and every pipeline picks it up.

  It is the least specific answer and loses to everything more specific:
  `~/.draugr/config.yaml` → `./draugr.config.yaml` → `$DRAUGR_API_URL` → `url:` in the Saga.
  Ambient-broad, ambient-narrow, ambient-immediate, then explicit — an environment variable is
  context, and a `url:` somebody wrote is intent.

  No token there, and there never will be: that file is committed, and a credential in it is a
  credential in somebody's git history.
