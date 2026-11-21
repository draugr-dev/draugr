# Editing the Saga schema

`pkg/saga/draugr.saga.schema.json` is **generated in full**, and so are
`pkg/saga/draugr.saga-fragment.schema.json` and `pkg/saga/draugr.config.schema.json`. An edit to
any of the three files is lost on the next `go generate`, and
`TestCheckedInSchemaIsUpToDate` in `internal/schemagen` fails until the file matches what the
generator writes.

## Where each part comes from

The descriptor's shape is read from `pkg/saga`'s types by `internal/schemagen/saga.go`:

- a struct becomes a definition, named in `sagaDefNames`, with `additionalProperties: false`
- a field becomes a property under its `yaml` key, typed from its Go type, so a `string` is
  `"type": "string"`, an `int` is `integer`, a pointer is the type it points to, a slice is an
  array and a map is an object whose values have the map's value type
- a field holding another struct is a `$ref` to that struct's definition

What a Go type cannot say comes from two tables in `internal/schemagen/sagafields.go`:

- `sagaFields`, keyed by definition and key (`publisherConfig.dir`), or by the key alone at the top
  of the file, holds each field's description and any constraint beside its type, such as a
  `pattern`, a `minLength` or a closed vocabulary
- `sagaDefinitions` holds each definition's description, the keys it requires, and any rule
  across its keys, such as the per-provider rules on `account`

A closed vocabulary is written with `vocab`, which takes the Go list the loader checks against and
a description for each value, and writes an `anyOf` of `const`. The rest comes from the plugin
registry:

- `controlName`, the `control_*` definitions and `controllers.properties`
- `config.allowEffects`, `reachabilityConfig.analyzers` and `reportConfig.format`
- the rules in `publisherConfig.allOf` marked `"$comment": "generated from pkg/publish"`, one per
  publisher kind, from what `pkg/publish` declares each kind reads, requires and delivers
- `fragmentControls` and `fragmentComponent`

The fragment schema is derived from the Saga schema. The config schema copies the Saga schema's
`controllers` definition and every `control_*` definition it refers to, and reads the rest from
`config.File` in `internal/schemagen/config.go`, which carries one description per key.

## Changing the schema

Change the Go type, or its entry in `sagafields.go`, then regenerate:

```bash
go generate ./pkg/saga/...
go test ./pkg/saga/ ./internal/schemagen/
```

Generation refuses to write a schema it cannot vouch for, and names what to fix when:

- a field of a descriptor struct has no entry in `sagaFields`, or an entry names a field that no
  longer exists
- a field that is not a reference to a definition has no description
- a struct reachable from a descriptor has no name in `sagaDefNames`, or a definition has no entry
  in `sagaDefinitions`
- a vocabulary offers a value the loader refuses, misses one it accepts, or has a value with no
  description

## Text is quoted

A field whose Go type is a string is typed `"type": "string"`. YAML reads an unquoted `true` as a
boolean and `1.10` as a number, and an editor holding the file to the schema marks either in a
text field. The loader keeps the literal text and warns, naming the field, its line and the quoted
value to write (`saga.UnquotedTexts`), and a later release refuses it as the schema already does.

The value of a map, such as a component's labels or an issue item's `fields`, keeps any scalar in
both readers, because its key is the author's own word and `pci: true` says what it means.

## Held to the loader

The parity tests change every field of every document under `examples/` and
`internal/cli/testdata/parity/` and require the schema and `draugr validate` to agree, counting the
quoting warning as `draugr validate` objecting. A new field has to be written as a live key in one
of those documents; when no example should carry it, write it in
`internal/cli/testdata/parity/fields.saga.yaml`.

The mutations also delete each key, and copy each key of a list item, account or cluster onto every
sibling that lacks it. That is what reaches a rule tying one key to another, such as `converter` on
a SARIF import or `tokenEnv` on an import that reads a file, and the schema writes each such rule as
`if`/`then` beside the definition it constrains.

A copied key needs a sibling of another kind to come from, so `TestEveryVariantIsInTheCorpus`
requires every value of a key that decides which keys its siblings may hold (an import's `format`
and `source`, a publisher's `kind`, `children` and `split`, an account's `provider`) to appear on an
item that has a sibling.
A rule no schema can state, a name declared in one place and used in another, is listed in
`parityExceptions` or `dropExceptions` with the reason.

`internal/schemagen/strictness_test.go` requires every string property to be closed or listed with
the reason it is open, and every object to refuse keys it does not list.

## Why this is not in the file

It was, as a `$comment`, which is the only way a JSON file carries one. That comment is also the
first thing `draugr schema` prints, the first thing an editor reads when somebody pins validation to
their build, and it is served from `draugr.dev/schema/`. A thousand characters about Go structs and
a test name is written for the person editing this repository, and it was being shown to everybody
who validates a descriptor.

The file keeps a one-line `$comment` pointing here, which is what a contributor with the repository
open needs and what a user can ignore.
