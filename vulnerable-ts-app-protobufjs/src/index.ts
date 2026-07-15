// Intentionally vulnerable demo — DO NOT DEPLOY
// CVE-2022-25878 (protobufjs@6.11.2) — CVSS 9.8

import * as protobuf from "protobufjs";

// CVE-2022-25878: protobufjs prototype pollution via util.setProperty.
export function decodeMessage(descriptor: string, buf: Uint8Array): any {
  const root = protobuf.parse(descriptor).root;
  const Msg = root.lookupType("demo.Msg");
  return Msg.decode(buf);
}
