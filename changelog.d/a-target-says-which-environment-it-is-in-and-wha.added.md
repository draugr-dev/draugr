**A target says which environment it is in, and what a scanner may do there.** `hosts[]` and `infrastructure[]` take an `environment`, and `config.allowEffects` can be keyed by it:

```yaml
config:
  allowEffects:
    staging: [mutate]
    production: []      # named, and accepting nothing
```

An effect happens to a target, so the permission is now resolved per target. A descriptor listing a staging endpoint and a production one used to permit an intrusive scan against both from one review of one file. A refusal names the environment that refused, so the fix is `config.allowEffects.production` rather than widening the permission to everything.

A plain `allowEffects: [mutate]` still means every environment, and `--allow-effects` still applies to the whole run. Findings from a target that declares an environment carry it, so a report can be read by where the finding actually is. Repositories and images take no environment: the same image digest may be deployed everywhere or nowhere.
