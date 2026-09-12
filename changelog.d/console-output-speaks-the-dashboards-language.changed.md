- **`draugr scan` output speaks the same visual language as the dashboard and the HTML report.**
  The verdict, the priority bands and the per-control severity counts are filled chips in the
  project's own colors, exactly matching on a terminal that can show them and falling back to the
  sixteen every terminal has. P3 has a color of its own for the first time, so all four bands are
  distinguishable. The run's elapsed time sits beside the verdict rather than only under
  `--evidence`, and a finding that carries a link to its rule now carries one to the line it was
  found on, pinned to the commit that was scanned.
