// Intentionally vulnerable demo — DO NOT DEPLOY
// CVE-2022-37601 (loader-utils@2.0.2) — CVSS 9.8

import * as loaderUtils from "loader-utils";

// CVE-2022-37601: loader-utils prototype pollution via parseQuery.
export function extractQueryOptions(loaderRequest: string): any {
  return (loaderUtils as any).parseQuery(loaderRequest);
}
