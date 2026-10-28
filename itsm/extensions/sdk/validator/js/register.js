"use strict";

// Fixed registration check: execute the candidate frontend with only the
// documented window.ITSMExtensions.register bridge, then report what it bound.
const path = require("path");

let registration = null;
globalThis.window = {
  ITSMExtensions: {
    register(id, value) {
      if (registration !== null) {
        throw new Error("register called more than once");
      }
      registration = { id, value };
    },
  },
};

try {
  const candidate = path.resolve(process.argv[2]);
  require(candidate);
  if (registration === null) {
    throw new Error("window.ITSMExtensions.register was not called");
  }
  if (typeof registration.id !== "string" || !registration.id) {
    throw new Error("registration id must be a non-empty string");
  }
  const value = registration.value;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("registration value must be an object");
  }
  const components = value.components;
  if (!components || typeof components !== "object" || Array.isArray(components)) {
    throw new Error("registration components must be an object");
  }
  const names = Object.keys(components);
  for (const name of names) {
    const component = components[name];
    if (!component || typeof component !== "object") {
      throw new Error("component " + name + " must be an object or Vue definition");
    }
  }
  const required = JSON.parse(process.argv[3]);
  if (!Array.isArray(required)) {
    throw new Error("required component list is invalid");
  }
  const missing = required.filter((name) => !names.includes(name));
  if (missing.length) {
    throw new Error("missing declared components: " + missing.join(", "));
  }
  process.stdout.write(
    JSON.stringify({ id: registration.id, components: names.sort() })
  );
} catch (error) {
  process.stderr.write(String((error && error.message) || error).slice(0, 500));
  process.exit(1);
}
