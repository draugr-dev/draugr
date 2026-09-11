- The progress display no longer erases lines it did not draw. On a window narrow enough to wrap
  one of its rows, each repaint moved the cursor up one row short and cleared whatever was above,
  so a scan quietly ate the output that was on screen before it started. Rows are now cut to the
  window.
