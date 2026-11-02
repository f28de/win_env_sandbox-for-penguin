import { defineConfig } from "tsup";

export default defineConfig({
  // The plugin the harness loads: the provider, the settings group and the card.
  //
  // The launcher is NOT an entry here. It has its own config (tsup.launcher.config.ts) and its
  // own build, for two reasons:
  //
  //   - the launcher is what every confined command runs, and it must be ONE self-contained
  //     file. Sharing modules with the plugin entry is what once let tsup hoist the launcher's
  //     entry check into a `chunk-*.js`, where it never fired and every confined command exited
  //     0 without running (see `src/launch.ts`);
  //   - the launcher imports NOTHING from `@prismshadow/penguin-core`, so it can be built —
  //     and tested — without core's own build being present. The test script builds it before
  //     the suites run, which is what keeps the built-artifact regression test from being
  //     silently skipped.
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node24",
  dts: true,
  clean: true,
  sourcemap: true,
  // koffi is a native-adjacent package with per-platform prebuilds: it is resolved from the
  // installation at run time, never inlined into the bundle.
  external: ["koffi"],
});
