"use strict";

const { execFileSync } = require("child_process");

const MIN_MAJOR = 3;
const MIN_MINOR = 11;

/**
 * Find a suitable Python >= 3.11 on PATH.
 * Tries python3 first, then python.
 * Returns the command name or null if none found.
 */
function findPython() {
  for (const cmd of ["python3", "python"]) {
    try {
      const raw = execFileSync(cmd, [
        "-c",
        "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
      ], { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }).trim();

      const [major, minor] = raw.split(".").map(Number);
      if (major === MIN_MAJOR && minor >= MIN_MINOR) {
        return cmd;
      }
    } catch {
      // command not found — try next
    }
  }
  return null;
}

module.exports = { findPython, MIN_MAJOR, MIN_MINOR };
