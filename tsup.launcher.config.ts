import { defineConfig } from "tsup";

/**
 * The launcher, built on its own.
 *
 * One entry, one file, no sharing with the plugin entry — and no dependency on
 * `@prismshadow/penguin-core`, which is what lets the test script build it before the suites
 * run (see `package.json`'s `test`): the built-artifact regression test then always has an
 * artifact to run, instead of skipping itself when `dist/` happens to be missing.
 *
 * `clean` is off: the plugin's own build writes `dist/index.js` into the same directory, and
 * this run must not wipe it. The package's `build` script therefore runs the plugin build
 * first and this one second.
 */
export default defineConfig({
  entry: ["src/launch.ts"],
  format: ["esm"],
  target: "node24",
  dts: false,
  clean: false,
  sourcemap: true,
  // One file, no chunk graph: the launcher is what `CreateProcessAsUserW` is handed.
  splitting: false,
  external: ["koffi"],
});
