A publisher that cannot use anything you render is refused when the descriptor loads, not after the
scan. `config.publishers: [{kind: github}]` with no `sarif` under `config.reports` used to cost a
whole pipeline to discover, and the message came from the publisher, telling you to go and edit a
different block. Each publisher now declares the formats it delivers, `draugr validate` and
`draugr scan` both check the pairing up front, and the reference table says what each one needs.
