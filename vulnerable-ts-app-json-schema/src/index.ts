// Intentionally vulnerable demo — DO NOT DEPLOY
// CVE-2021-3918 (json-schema@0.2.3) — CVSS 9.8

import * as jsonSchema from "json-schema";

// CVE-2021-3918: json-schema prototype pollution.
// Attacker-supplied schema can pollute Object.prototype.
export function validateSchema(untrustedSchema: any, data: any): boolean {
  const result: any = (jsonSchema as any).validate(data, untrustedSchema);
  return result.valid;
}
