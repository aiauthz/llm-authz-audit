"use strict";

/**
 * postinstall script — eagerly sets up the Python venv.
 * Failures are non-fatal (the venv will be created on first run).
 */

const { isReady, setup } = require("./lib/venv-manager");

if (!isReady()) {
  try {
    setup();
  } catch (err) {
    console.warn(
      `\nllm-authz-audit: postinstall setup skipped — ${err.message}\n` +
      `The tool will retry setup on first run.\n`
    );
  }
}
