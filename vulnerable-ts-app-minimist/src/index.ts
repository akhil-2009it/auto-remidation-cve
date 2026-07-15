// Intentionally vulnerable demo — DO NOT DEPLOY
// CVE-2021-44906 (minimist@1.2.5) — CVSS 9.8

import minimist from "minimist";

// CVE-2021-44906: minimist prototype pollution via --__proto__ argv.
export function parseCliArgs(argv: string[]): any {
  return minimist(argv);
}
