- The example descriptors write every control, every publisher and every scanner option. `dast`
  and `threats` appeared in none of them, five of the six publishers appeared only in
  `reporting.saga.yaml`, and twenty-four scanner options, the kube-bench and Mend blocks among
  them, were in the schema and in no file anybody could copy. `examples/scanner-options.saga.yaml`
  is new and holds the last of those. Three guards keep the set honest: a control, a publisher or
  a scanner option added from now on fails the build until an example writes it.
