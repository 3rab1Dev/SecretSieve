# Privacy Model

Copyright (c) 3rabDev - https://3rabdev.online

SecretSieve is local-first. These are guarantees, not aspirations:

1. **No internet required.** The scan path performs zero socket operations.
2. **No uploads.** Source code never leaves the machine.
3. **No secret transmission.** There is no verification-against-provider feature (it would transmit secrets); none is planned.
4. **No telemetry.** None shipped, none planned. Any future network feature would be opt-in, explicit, and documented - and would never send findings.
5. **Redacted output.** Previews are fixed-length masks (`AKIA****************9X2F`); JSON carries `redacted` + `value_hash` only. No raw-value field exists in the schema.

Verify it yourself: block the network and scan; or grep the scan path
(`src/secretsieve/scanner`, `src/secretsieve/detectors`) for `socket`,
`requests`, `urllib`, `http.client` - there are none (enforced by test).
