# Synthetic MCP pre-access authorization test harness

A **local, disposable demonstration** of why a valid credential for an HTTP MCP resource server is not enough to authorize a downstream operation. This is an in-process synthetic fixture using two loopback HTTP servers. It is **not** a conforming MCP server, a production OAuth authorization server, an actual industrial control system, an interoperability certificate, or a production security assessment.

The test case is a fabricated maintenance record system with Sites A and B. A synthetic opaque bearer token maps to an issuer, audience, subject, site, operations and expiry. The gateway independently checks the requested tool, operation, site and parameter; it invokes a separate loopback target endpoint with a service credential that is **not** the caller's MCP token. A deliberately permissive mode demonstrates the incorrect outcome before restrictions are restored.

## Run the test

Requires CPython **3.13.5** (the version used for the recorded run); all dependencies are from the standard library. No external packages, cloud services, network access beyond `127.0.0.1`, production credentials, tools or live machinery are used.

```sh
python3 harness.py
```

The command binds random loopback ports, performs **16 predefined cases x 3 repetitions = 48 checks**, writes `evidence.json`, and exits nonzero if an assertion fails. The checked-in `evidence.json` is one run, not an externally reproduced finding. Rerunning changes timestamps and random ephemeral tokens, which are never exported.

The cases include authorized read/write, an intentionally insecure baseline that changes the other site's value, the restricted equivalent (must deny without changing state), operation and site scope, an out-of-range parameter, missing/unknown/expired/wrong-audience/wrong-issuer credentials, mismatched or missing mirrored HTTP headers, a direct-target attempt without the downstream service credential, policy-service unavailability, and grant revocation. The fixture records gateway decisions separately from target operations and checks that denied requests do not create target-side events. A denied response with an unexpected target change fails.

## Boundaries and evidence limitations

- The gateway and target are separate loopback HTTP servers but share a **single Python process and in-memory `State` object**. Their log separation is useful for this exercise, but it is **not evidence isolation from a compromised gateway**. A stronger study must put the target, audit log and policy authority in separate processes or hosts with independent access controls.
- The synthetic opaque-token registry models token validation. It does not implement OAuth, introspection, JWT cryptography, or the normative July 2026 MCP authorization specification.
- The fixture models only a small subset of `tools/call` and Streamable HTTP request metadata. HTTP status/error behavior is **locally defined for this demonstration** and must not be presented as proof of MCP protocol conformance.
- All operations are synchronous. There are **no delayed jobs, retries, approval artifacts or scheduling queues** to inspect. The run checks for additional events after a one-second settling interval. This cannot substitute for a 60-second or longer observation window when asynchronous work is present. Approval-reuse is **not applicable**.
- Three repetitions are enough to repeat this bounded example, **not** to estimate reliability, industrial safety or security against prompt injection. No model or actual SDK is invoked.
- This code and its outputs are preliminary test artifacts for editorial review, not a published article or an editor's acceptance.

Primary technical context: [MCP July 2026 HTTP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [MCP July 2026 Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports), [NIST SP 800-82 Rev. 3 final](https://csrc.nist.gov/pubs/sp/800/82/r3/final). These sources provide requirements and operational context; this synthetic fixture implements neither an official reference server nor an OT control system.
