"use strict";

const path = require("path");
const fs = require("fs");
const { execFileSync } = require("child_process");
const { findPython, MIN_MAJOR, MIN_MINOR } = require("./python-resolver");

const VENV_DIR = path.join(__dirname, "..", ".venv");
const PIP_PACKAGE = "llm-authz-audit";
const REPO_ROOT = path.join(__dirname, "..", "..");

/**
 * Return the path to the Python binary inside the venv.
 */
function venvPython() {
  const isWin = process.platform === "win32";
  return path.join(VENV_DIR, isWin ? "Scripts" : "bin", isWin ? "python.exe" : "python");
}

/**
 * Check whether the venv exists and has the package installed.
 */
function isReady() {
  const py = venvPython();
  if (!fs.existsSync(py)) return false;
  try {
    execFileSync(py, ["-m", "llm_authz_audit", "--help"], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Create the venv and install the package.
 * Throws on failure.
 */
function setup() {
  const python = findPython();
  if (!python) {
    throw new Error(
      `Python >= ${MIN_MAJOR}.${MIN_MINOR} is required but was not found on PATH.\n` +
      `Install Python from https://www.python.org/downloads/ and try again.`
    );
  }

  // Create venv
  if (!fs.existsSync(VENV_DIR)) {
    execFileSync(python, ["-m", "venv", VENV_DIR], { stdio: "inherit" });
  }

  // Install package
  const pip = venvPython();
  execFileSync(pip, ["-m", "pip", "install", "--upgrade", "pip"], {
    stdio: "inherit",
  });

  // If running from within the git repo, install from local source (dev mode).
  // Otherwise, install from PyPI.
  const localPyproject = path.join(REPO_ROOT, "pyproject.toml");
  if (fs.existsSync(localPyproject)) {
    execFileSync(pip, ["-m", "pip", "install", "-e", REPO_ROOT], {
      stdio: "inherit",
    });
  } else {
    execFileSync(pip, ["-m", "pip", "install", PIP_PACKAGE], {
      stdio: "inherit",
    });
  }
}

module.exports = { venvPython, isReady, setup, VENV_DIR };
