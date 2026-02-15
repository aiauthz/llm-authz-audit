"use strict";

const { spawnSync } = require("child_process");
const { venvPython, isReady, setup } = require("./venv-manager");

/**
 * Run the llm-authz-audit CLI, forwarding all arguments and the exit code.
 */
function run(args) {
  // Ensure venv is ready
  if (!isReady()) {
    try {
      console.error("Setting up llm-authz-audit (first run)...");
      setup();
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(2);
    }
  }

  const result = spawnSync(venvPython(), ["-m", "llm_authz_audit", ...args], {
    stdio: "inherit",
  });

  if (result.error) {
    console.error(`Failed to run llm-authz-audit: ${result.error.message}`);
    process.exit(2);
  }

  process.exit(result.status ?? 1);
}

module.exports = { run };
