const minimist = require("minimist");

// ruleid: draugr-fixture-eval
module.exports.run = (code) => eval(code);

// ok: draugr-fixture-eval
module.exports.parse = (text) => JSON.parse(text);

module.exports.args = (argv) => minimist(argv);
