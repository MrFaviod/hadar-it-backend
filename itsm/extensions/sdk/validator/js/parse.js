"use strict";

// Fixed syntax check: compile the candidate frontend without executing it.
const fs = require("fs");

try {
  const source = fs.readFileSync(process.argv[2], "utf8");
  new Function(source);
  process.stdout.write("syntax-ok");
} catch (error) {
  process.stderr.write(String((error && error.message) || error).slice(0, 500));
  process.exit(1);
}
