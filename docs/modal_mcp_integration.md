# The Modal MCP server

The Modal MCP server is a small, protected HTTP interface in front of the
Modal workspace of this repository. It lets a chat client - ChatGPT, for
example - ask the workspace questions and run the CPU audit of the service,
without giving the client a shell and without giving the client a credential
of its own.

The implementation lives in `integrations/modal_mcp/`. It is a standalone
package: it imports nothing from `core/` and nothing from `sandbox/`, so it
can neither change an entry of the R1 dispatch registry nor weaken the
fail-closed approval of the benchmark.

---

## 1. What it is

* **Transport** - MCP over Streamable HTTP, at the path `/mcp`.
* **Runtime** - a CPU-only Modal application. It declares `gpu=None`, so it
  cannot allocate an accelerator, not even by accident.
* **Credential** - a dedicated Modal API token, stored in the Modal Secret
  `modal-mcp-credentials`. The server builds its client from that token
  explicitly; it never falls back to an ambient credential.
* **Boundary** - a fixed list of named operations. There is no tool that runs
  an arbitrary command and no tool that reads an arbitrary path.

## 2. The tools

| Tool | Kind | What it does |
|---|---|---|
| `modal_status` | read | The state of the workspace, the environment and the allowlist of the server. |
| `modal_list_apps` | read | The applications of the environment with their state. |
| `modal_app_status` | read | The state of one application. |
| `modal_function_status` | read | The state of one function of one application. |
| `modal_logs` | read | The last log entries of one application. |
| `modal_billing` | read | The billing summary of the workspace for the current month. |
| `modal_run_cpu_audit` | executes | Runs the CPU audit of the service on one repository-owned target. |
| `modal_read_evidence` | read | Reads the stored result of one audit run back from the results volume. |
| `modal_list_evidence` | read | Lists the stored runs of the audit service. |
| `modal_environment_probe` | read | Asks the service for the state of its own environment (volumes, toolchain, GPU state). |
| `modal_run_tests` | executes | Runs one of the allowed smoke suites (`probe`, `evidence_readback`, `candidate_registry`). |
| `modal_deploy_dev` | mutates | Deploys into a development environment. **Switched off by default.** |
| `modal_stop_app` | mutates | Stops one explicitly named application. **Switched off by default.** |

The annotations of the tools (`readOnlyHint`, `destructiveHint`) are set
correctly, so that a chat client can call the read-only tools without asking
for a confirmation and warns before a write.

## 3. The security model

* **Allowlist** - only `aegis-rlvr-cpu-audit` and only its three functions
  (`audit_contract`, `read_saved_result`, `probe_environment`) are reachable.
  An application, a function or an environment outside the allowlist is
  refused with a named reason.
* **Authorisation before work** - a request for `/mcp` without a valid
  credential is refused with `401` before it reaches a tool, so an
  unauthenticated request can never start anything.
* **Replay protection** - every call that starts work needs a `request_id`.
  The identifier and the fingerprint of the request are kept in a ledger: the
  same request is executed once, and an identifier that was used for another
  request is refused.
* **Write operations** - `modal_deploy_dev` and `modal_stop_app` need both
  the write switch of the server (`MODAL_MCP_WRITE_ENABLED`) and the
  confirmation value of the owner. The switch is off by default.
* **No secrets in the output** - a result never carries a credential. The
  journal of the server writes names, states, digests and measurements; a
  field that looks like a credential is redacted before it is written.
* **No bypass of the fail-closed rules of the project** - the server does not
  import the R1 registry, does not touch the approval key and does not
  dispatch anything in production.

## 4. The two ways to authorise a call

### 4.1 The static bearer token of the owner

The owner calls the endpoint with a header:

```bash
curl -sS https://<workspace>--modal-mcp.modal.run/mcp \
  -H "Authorization: Bearer <the static bearer token>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

The value is written into a protected local file by the deployment, see
section 7.

### 4.2 OAuth 2.1 - the way a chat client calls it

The dialog of ChatGPT for a custom MCP server offers `OAuth`, `No
authentication` and a mixed mode. It has **no** field for a bearer token or
for a custom header, so a server that wants a real credential has to speak
OAuth. The server therefore implements a small authorization server:

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/oauth-authorization-server` | the metadata of the authorization server (RFC 8414) |
| `GET /.well-known/oauth-protected-resource` | the metadata of the protected resource (RFC 9728) |
| `POST /register` | the dynamic registration of a client (RFC 7591) |
| `GET /authorize` | the consent page |
| `POST /authorize` | the approval of the consent page |
| `POST /token` | the exchange of a code or of a refresh token for an access token |

The flow is the authorization code flow with PKCE; only `S256` is accepted.
The consent page is closed: it asks for the **enrolment code** of the owner.
A visitor without that code cannot enrol a client, so the endpoint cannot be
taken over by whoever learns the URL.

## 5. The deployment

```bash
# 1. the credentials of the server (a dedicated Modal token, the bearer token
#    of the owner, the enrolment code and the shared authorisation token of
#    the CPU audit service)
modal secret create modal-mcp-credentials --from-json <file> --profile <workspace>

# 2. the deployment
modal deploy integrations/modal_mcp/modal_mcp_app.py --profile <workspace>
```

The endpoint has a fixed label, so the public URL does not change between the
deployments:

```
https://<workspace>--modal-mcp.modal.run/mcp
```

The application is CPU-only, has no web route other than the MCP endpoint and
the OAuth endpoints, and mounts the results volume of the audit service
read-only.

### The variables of the server

| Variable | Where it comes from | Meaning |
|---|---|---|
| `MODAL_MCP_TOKEN_ID` | the Modal Secret | the identifier of the dedicated Modal token |
| `MODAL_MCP_TOKEN_SECRET` | the Modal Secret | the secret of the dedicated Modal token |
| `MODAL_MCP_ACCESS_TOKEN` | the Modal Secret | the static bearer token of the owner |
| `MODAL_MCP_ENROLLMENT_CODE` | the Modal Secret | the code of the consent page |
| `AEGIS_CPU_AUDIT_TOKEN` | the Modal Secret | the shared authorisation token of the CPU audit service |
| `MODAL_MCP_ISSUER` | the image | the public URL, used as the issuer of the authorization server |
| `MODAL_MCP_ALLOWED_APPS` | the environment | the applications that may be used |
| `MODAL_MCP_ALLOWED_FUNCTIONS` | the environment | the functions that may be called |
| `MODAL_MCP_ALLOWED_ENVIRONMENTS` | the environment | the environments that may be used |
| `MODAL_MCP_WRITE_ENABLED` | the environment | whether the write operations exist at all |
| `MODAL_MCP_REQUIRE_AUTH` | the environment | whether a request without a credential is refused |

The names of the two Modal variables are deliberately **not** `MODAL_TOKEN_ID`
and `MODAL_TOKEN_SECRET`: a Modal container already carries the credentials of
its own workspace under those names, and the server has to use the dedicated
credential it was configured with.

## 6. The local run

```bash
# the server on 127.0.0.1:8765, with the credential of the active local
# Modal profile
python -m integrations.modal_mcp --use-local-profile

# the same server without the authorisation (only for a local experiment)
python -m integrations.modal_mcp --use-local-profile --require-auth false
```

The local run serves the same ASGI application with the same authorisation,
so a call against it proves the same thing as a call against the deployment.

## 7. The connection in ChatGPT

1. Open <https://chatgpt.com/plugins>.
2. Select the plus button and **Add custom MCP server**.
3. Enter the name and the description of the server.
4. Under **Connection**, enter the endpoint, including the path:
   `https://<workspace>--modal-mcp.modal.run/mcp`.
5. Set the authentication to **OAuth**. The server publishes its metadata at
   `/.well-known/oauth-authorization-server` and registers clients itself, so
   no client id has to be entered by hand.
6. When the consent page opens, enter the **enrolment code** of the owner. It
   is in the protected local file that the deployment writes (see below).
7. Accept the risk warning, create the plugin, install it and start a new
   conversation with `@` on the plugin.

**The account decides what is possible.** According to the documentation of
OpenAI, the custom MCP servers of the *Plugins* experience are available to
Business, Enterprise and Edu workspaces; on an individual Plus or Pro plan the
read-only tools are available through the developer mode, while the tools that
change something stay in the hands of the workspace. The write tools of this
server are switched off in any case, so nothing can be changed from a chat.

The bearer token and the enrolment code are written into a protected file on
the machine of the owner:

```
C:\Users\Telekom\.minimax\secrets\modal-mcp-credentials.txt
```

The dedicated Modal token itself is **not** written there: it lives only in
the Modal Secret `modal-mcp-credentials`.

## 8. The tests

```bash
python -m pytest tests/test_modal_mcp.py -q
```

The tests are hermetic: they need neither a Modal account nor a network. The
access layer is replaced by a fake, so that the tests prove the policy of the
server and not the behaviour of the API of Modal.

## 9. The known limits of the first stage

* The write operations are implemented but switched off; `modal_deploy_dev`
  additionally refuses, because the deployment of an application needs the
  source of that application inside the image of the server.
* The MCP endpoint is public. The protection is the credential: a request
  without one is refused before it reaches a tool. The DNS-rebinding
  protection of the SDK is switched off deliberately, because it accepts only
  the hosts of the local machine and the host of the deployment changes with
  it.
* The server calls the CPU audit service with the shared authorisation token
  of that service. Without that token the CPU tools refuse themselves with
  `CPU_AUTH_TOKEN_MISSING` - the server never invents a verdict and never
  pretends that the audit ran.
* `modal_read_evidence` reads the artifact through the **API of the volume**,
  not through the container of the audit service. The reason is a defect of
  the CPU audit service that this integration found: `read_saved_result` reads
  the volume without reloading it, and a container that was started before a
  commit keeps the snapshot of the volume it was started with. A run that was
  committed after that moment is invisible to such a container - it answers
  `NOT_FOUND` although the artifact is in the volume. The read-back of the
  service itself is reported next to the artifact, so that the disagreement
  is visible instead of hidden. The fix on the side of the service is one
  line (`volume.reload()` before the read); it belongs to the branch of the
  CPU audit service, not to this one.
