# The Modal SDK 1.5.5 compatibility of the D27 autoscaler read-back — 2026-11-14

This iteration closes the repository defect that the read-only evidence iteration of
2026-11-14 reported but did not fix: the D27 read-back awaited the **synchronous**
public Modal client.

**No live dispatch, no spend.** The only RPC issued while measuring this was the
read-only `FunctionGet` control-plane read for an app that does not exist; the server
answers `NotFoundError`. No deployment, no function invocation, no GPU/H100
allocation, no Volume operation, no model download, no spend. `PINNED_PUBLIC_KEY`
stays `null`, no approval artifact was created or signed, the rate card stays
unapproved, no `Unset` bound was changed, R2p/R3/R3b/R4 were not run, the dispatch
gate was not weakened, and the PR stays **Draft**.

---

## 1. The defect — measured, not assumed

`benchmarks/r1_dispatch.py` built the provider client with

```python
client = await Client.from_env()
```

and `modal.client.Client` is the **synchronous** wrapper of Modal SDK 1.5.5:

| | |
|---|---|
| SDK definition | `Client = synchronize_api(_Client)` (`modal/client.py:532`) |
| `Client.from_env` | a **synchronous** function — it returns the client, it is not awaitable |
| `_Client.from_env` | an **asynchronous** classmethod (`async def`, `modal/client.py:238`) |
| The RPC itself | asynchronous in both cases: the generated stub is `modal._grpc_client.UnaryUnaryWrapper` and its `__call__` is `async def` |
| Observed error | `TypeError: object Client can't be used in 'await' expression` |
| Effect | `provider_autoscaler_reader` failed closed with `AutoscalerReadbackUnavailable` against **every** deployment — independently of the deployment state |

The defect was invisible to the test suite, because the test replaced the real API
with a fake: `monkeypatch.setattr(Client, "from_env", staticmethod(fake_from_env))`
installed an **async** double on a **synchronous** attribute. The double matched the
code, not the SDK.

## 2. The measured call chain — nine paths, one subprocess each

The paths were measured with `benchmarks/evidence/r1_sdk_compat_20261114/collection_scripts/probe_client_paths.py`
(raw output: `benchmarks/evidence/r1_sdk_compat_20261114/raw_client_paths.txt`,
machine-readable: `.../sdk_client_paths.json`). Every path runs in its own process
with a hard 40 s timeout, so a blocking path cannot hide.

| Path | Arrangement | Outcome |
|---|---|---|
| 1 | **the defective code** — `await Client.from_env()` | `TypeError: object Client can't be used in 'await' expression` |
| 2 | `await _Client.from_env()` in one event loop | `NotFoundError` — the control plane answers |
| 3 | the same, twice, each in its own event loop | `NotFoundError` twice |
| 4 | public **sync** client, the stub coroutine awaited in a fresh loop | **timeout — the path blocks** |
| 5 | public **sync** client first, then the asynchronous read | **timeout — the path blocks** |
| 6 | public sync client, the stub coroutine on the synchronizer's loop | `NotFoundError` |
| 7 | **`synchronize_api`** around the asynchronous read — **the shipped fix** | `NotFoundError` |
| 8 | the shipped fix, **after** the public sync client exists | `NotFoundError` — no deadlock |
| 9 | the shipped fix, called twice | `NotFoundError` twice |

Two findings shaped the fix:

1. **The read must not await the public client** (path 1) — that is the defect itself.
2. **The read must not run on a private event loop** (paths 4 and 5): the client
   singleton belongs to the loop that created it, and the public synchronous client
   creates it on the SDK's synchronizer loop. A read on a private loop then **blocks
   forever** instead of failing closed — and the public synchronous client *is*
   created in the dispatch flow, because the provider resolves Modal objects. A
   "fix" that only replaced `Client` with `_Client` would therefore have turned a
   refusal into a hang in exactly the situation the gate runs in.

## 3. The fix

`benchmarks/r1_dispatch.py` now builds the read-only call through the SDK's own
synchronisation machinery, `synchronize_api`:

```python
@synchronize_api
async def _function_get(request: Any) -> Any:
    client = await _Client.from_env()
    return await client.stub.FunctionGet(request)
```

* the **asynchronous** client is used, and the public synchronous client is never
  touched — the reader itself stays synchronous;
* the coroutine runs on the **Modal synchronizer's own loop**, which is the loop the
  public synchronous client uses as well, so the client singleton, the gRPC channel
  and the provider objects of the process share one loop (paths 7–9);
* `_run_coroutine_blocking` — the helper that started a *private* loop per call — is
  removed, because that arrangement is the deadlock of paths 4 and 5;
* everything else is unchanged: the request is the same `FunctionGetRequest` with the
  same app, object tag, environment and app version, the protobuf presence checks
  are the same, the opt-in gate `R1_ENABLE_PROVIDER_READBACK=1` is the same, and
  every failure is still an *unavailable* read and never a partial one.

## 4. The tests

`tests/test_r1_readback_sdk_compat.py` (new, 12 tests):

| Test | What it pins |
|---|---|
| `test_the_public_modal_client_is_synchronous_and_the_private_one_is_not` | the SDK fact itself, against SDK drift |
| `test_the_read_back_source_does_not_await_the_synchronous_public_client` | the defective expression is gone from the reader |
| `test_the_read_back_uses_the_asynchronous_client` | the four effective settings are read |
| `test_the_read_back_never_uses_the_synchronous_public_client` | the public client is a double that raises when touched — the read passes anyway |
| `test_the_read_back_sends_the_authoritative_function_get_request` | app, object tag, environment and app version of the request |
| `test_the_read_back_runs_the_rpc_on_the_modal_synchronizer_loop` | the RPC runs on `synchronizer._loop` — the deadlock-free arrangement |
| `test_the_read_back_can_be_repeated_in_one_process` | a second read-back in the same process still works |
| `test_a_client_failure_fails_closed` | a client that cannot be built → `AutoscalerReadbackUnavailable` |
| `test_an_rpc_failure_fails_closed` | an RPC that fails → unavailable, and the gate refuses the step with `autoscaler_readback_unavailable` |
| `test_the_read_back_is_refused_without_the_explicit_opt_in` | without the opt-in the provider is not contacted at all |
| `test_the_read_back_never_issues_the_mutating_autoscaler_rpc` | `FunctionUpdateSchedulingParams` — the mutating RPC's request — is never built |
| `test_the_provider_object_is_never_asked_to_update_its_autoscaler` | the provider object of the call site is only read, never mutated |

`tests/test_r1_dispatch_contract.py` — the existing read-back test patched the
synchronous public client with an async double. It now patches the **asynchronous**
client, so the test exercises the real API shape instead of a fictional one.

### The commands and their results

```
$ python -m pytest tests/test_r1_readback_sdk_compat.py -q
12 passed in 0.20s

$ python -m pytest tests/ -q
1036 passed, 7 skipped in 124.69s (0:02:04)
```

The full suite is the same command the CI job `Reward v2 and trusted harness
regression suite` runs (`python -m pytest -q --junitxml=test-results.xml`).

## 5. What remains `UNAVAILABLE`

The **live** autoscaler read-back is still `UNAVAILABLE`, and this iteration does
not change that: the app `aegis-rlvr-security` does not exist in the `main`
environment, so the read-only `FunctionGet` is answered with

```
NotFoundError: App 'aegis-rlvr-security' not found in environment 'main'
```

What this iteration establishes is different and narrower: **the reader is no longer
the reason the read-back fails**. Against SDK 1.5.5 the reader now builds the client
correctly and issues the read-only RPC; what the read returns is a fact about the
deployment, not a defect of the repository. A successful read requires an
independently authorised deployment, which does not exist and which R1 does not
create.

R1 therefore stays **NOT ACCEPTED / PROVISIONAL_ONLY / NOT_DISPATCHABLE**, and this
is not R1 acceptance.

## 6. The artefacts

| Artefact | Content |
|---|---|
| `benchmarks/evidence/r1_sdk_compat_20261114/collection_scripts/probe_client_paths.py` | the probe: nine client paths, one subprocess each, hard timeout, read-only |
| `benchmarks/evidence/r1_sdk_compat_20261114/raw_client_paths.txt` | the verbatim outcome of every path |
| `benchmarks/evidence/r1_sdk_compat_20261114/sdk_client_paths.json` | the same, machine-readable, with the timestamp and the SDK version |
| `docs/r1_sdk_compat_report_20261114.md` | this report |
