package report

// AssertGolden is assertGolden for the tests in report_test, which draw a run's change with
// pkg/diff and so cannot be in this package, since pkg/diff imports it.
var AssertGolden = assertGolden
