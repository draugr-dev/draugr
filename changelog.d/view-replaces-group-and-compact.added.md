- **`--view` replaces `--group` and `--compact`, which were one question asked twice.**
  `--view findings` is the default, a row per finding with what argued with its band underneath;
  `--view actions` leads the report with the work, one row per thing to do; `--view compact` gives
  one line each, trimmed to your terminal, and in `json` and `sarif` strips indentation and relayed
  rule prose for a consumer that parses rather than reads. Both old flags still work and name what
  to write instead, and `config.output.group` became `config.output.view`.
