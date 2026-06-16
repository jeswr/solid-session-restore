// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// check-dist.mjs — fail if the committed `dist/` drifts from a fresh build.
//
// This package commits its built `dist/` so a consumer can `npm install
// github:jeswr/solid-session-restore#main` and import it under `ignore-scripts=true`
// with NO build step. That only stays honest if the committed artifact matches the
// source: this gate rebuilds into a TEMP dir and byte-compares every emitted file
// against the committed `dist/`. A mismatch (or a missing/extra file) fails — the
// fix is `npm run build` + commit.
//
// stdlib-only Node ESM (no new dependency). Run via `npm run check:dist`.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const committedDist = join(root, "dist");
// Build the comparison copy as a SIBLING of dist/ INSIDE root (same directory
// depth), so source-map relative `sources` paths (map → src) match the committed
// build exactly — a temp dir elsewhere on disk shifts those relative paths and
// makes the .map byte-comparison spuriously fail.
const tmp = join(root, ".dist-check");

/** Recursively list every file under a dir, as paths relative to that dir (sorted). */
function listFiles(dir) {
  const out = [];
  const walk = (d) => {
    let entries;
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      return; // missing dir → empty listing
    }
    for (const e of entries) {
      const full = join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile()) out.push(relative(dir, full));
    }
  };
  walk(dir);
  return out.sort();
}

const sha = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

function fail(msg) {
  console.error(`check:dist FAILED — ${msg}`);
  console.error("Fix: run `npm run build` and commit the updated dist/.");
  process.exit(1);
}

// 1. The committed dist must exist (the whole point — a buildless GitHub install).
try {
  if (!statSync(committedDist).isDirectory()) fail("dist/ is not a directory");
} catch {
  fail("dist/ is missing — it must be committed");
}

// 2. Build fresh into the sibling outDir (cleaned first / on exit).
rmSync(tmp, { recursive: true, force: true });
try {
  execFileSync(
    process.execPath,
    [
      join(root, "node_modules", "typescript", "bin", "tsc"),
      "-p",
      join(root, "tsconfig.build.json"),
      "--outDir",
      tmp,
    ],
    { stdio: "inherit", cwd: root },
  );

  // 3. Compare the file SETS.
  const committed = listFiles(committedDist);
  const fresh = listFiles(tmp);
  const committedSet = new Set(committed);
  const freshSet = new Set(fresh);
  const missing = fresh.filter((f) => !committedSet.has(f));
  const extra = committed.filter((f) => !freshSet.has(f));
  if (missing.length) fail(`committed dist/ is MISSING files: ${missing.join(", ")}`);
  if (extra.length) fail(`committed dist/ has STALE/EXTRA files: ${extra.join(", ")}`);

  // 4. Byte-compare each file (hash).
  const drifted = fresh.filter((f) => sha(join(committedDist, f)) !== sha(join(tmp, f)));
  if (drifted.length) fail(`committed dist/ DIFFERS from a fresh build: ${drifted.join(", ")}`);

  console.log(`check:dist OK — committed dist/ matches a fresh build (${fresh.length} files).`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
