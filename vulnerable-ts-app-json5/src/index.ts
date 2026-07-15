// Intentionally vulnerable demo — DO NOT DEPLOY
// CVE-2022-46175 (json5@2.2.0) — CVSS 9.8

import JSON5 from "json5";

// CVE-2022-46175: json5 prototype pollution via __proto__ keys.
export function parseUserConfig(rawJson5: string): any {
  return JSON5.parse(rawJson5);
}
