/**
 * The launcher's entry file: run one job, exit with the command's own status.
 *
 * This is a separate file from `runner.ts` on purpose, and the reason is a build failure worth
 * remembering. `runner.ts` used to decide for itself whether it was the entry —
 * `import.meta.url === pathToFileURL(process.argv[1]).href` — which is true only while the
 * bundler keeps that line in the file `process.argv[1]` names. With two entries and code
 * splitting on, tsup moved the shared modules into `chunk-*.js` and the guard went with them;
 * inside the chunk `import.meta.url` is the CHUNK's URL, so the comparison was never true,
 * `main()` never ran, and every confined command exited 0 having executed nothing. The worst
 * failure mode a sandbox launcher can have: silent success.
 *
 * An entry file with an unconditional call cannot be moved, split or tree-shaken away. Nothing
 * in the harness imports this file; `launcherPath()` points at the built `launch.js`.
 */
import { main } from "./runner.js";

process.exit(main(process.argv.slice(2)));
