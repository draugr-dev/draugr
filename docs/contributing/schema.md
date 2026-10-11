# Editing the Saga schema

`pkg/saga/draugr.saga.schema.json` is **half authored and half overwritten**, and the line between
them is not obvious from reading the file.

## The authored half

Definitions describing the descriptor's own shape, `component`, `host`, `repository`, `gateConfig`
and the rest, are written by hand and guarded.

`TestSchemaCoversEveryModelField` in `pkg/saga` reflects over the Go structs in both directions, so
a property whose field no longer exists fails the build, and so does a field with no property.

## The generated half

These come from the live plugin registry and **any edit to them is lost**:

- `controlName`
- the `control_*` definitions
- `controllers.properties`
- `config.allowEffects`
- `reportConfig.properties.format`
- the rules in `publisherConfig.allOf` marked `"$comment": "generated from pkg/publish"`, one per
  publisher kind, from what `pkg/publish` declares each kind reads, requires and delivers

Generated rather than guarded, because `pkg/saga` cannot import the registry without a cycle, so no
test is in a position to compare the two.

The publisher rules come from the declarations `draugr validate` reads (`reads`, `requires` and
`accepts` in `pkg/publish/fields.go`), so the schema and `draugr validate` refuse the same fields on
each kind. A field added to `PublisherConfig` is refused on every kind until it is named there.

## Held to the loader

The parity tests change every field of every document under `examples/` and
`internal/cli/testdata/parity/` and require the schema and `draugr validate` to agree. A new field
has to be written as a live key in one of those documents; when no example should carry it, write
it in `internal/cli/testdata/parity/fields.saga.yaml`.

## After changing a descriptor struct

```bash
go generate ./pkg/saga/...
go test ./pkg/saga/ ./internal/schemagen/
```

Edit the definition in the authored half first, then regenerate. Running it the other way round
looks like it worked and loses the edit.

## Why this is not in the file

It was, as a `$comment`, which is the only way a JSON file carries one. That comment is also the
first thing `draugr schema` prints, the first thing an editor reads when somebody pins validation to
their build, and it is served from `draugr.dev/schema/`. A thousand characters about Go structs and
a test name is written for the person editing this repository, and it was being shown to everybody
who validates a descriptor.

The file keeps a one-line `$comment` pointing here, which is what a contributor with the repository
open needs and what a user can ignore.
