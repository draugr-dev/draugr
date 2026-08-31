- `builtBy` now works on a **repository** and on a **component**, not only on an image. Declare it
  once on a component that is entirely somebody else's software and it covers every target under
  it; a repository or an image may override it. It changes what the report tells you to do and
  nothing else — the finding keeps its severity and its band, is still counted, and still reaches
  the gate. Licenses are where it is felt most: a denied license in the dependency tree of a
  repository you do not publish is not one you chose and not one you can swap out, so the report
  stops telling you to change code you do not own.
