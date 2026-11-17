# The generation of the R1 approval key pair

**Who this document is for.** The maintainer (the approval authority) of this
repository. It is the procedure you follow **locally, on your own machine**, when
you decide to pin an approval key.

**What this document does not do.** It does not generate a key, and it does not
approve anything. Nothing in this repository generates a key pair, and no step
of the evidence-regeneration workflow is approved by the existence of this
document. The owner pinned the **public** half of the approval key pair on
2026-11-15 (`core/r1_approval.py::PINNED_PUBLIC_KEY` carries the RSA-4096
modulus and the exponent `65537`; the mirror
`benchmarks/evidence/r1_approval_key.json` carries the same key), and the
private half stays with the owner: it never enters this repository, it never
enters a process of the workflow, and it is never handed to an agent, a chat, a
CI job or a commit. A pin is not an approval: no approval artifact exists
here, so **no provider dispatch is possible** and every stage of the workflow
stays `PROVISIONAL_ONLY` / `NOT_DISPATCHABLE`.

**The boundary.** The private half of the key is *yours* and stays with you. It
never enters this repository, it never enters a process of the workflow, and it
is never handed to an agent, a chat, a CI job or a commit. What the repository
receives is the **public** half only - the modulus `n` and the exponent
`e = 65537` - and only after you have explicitly permitted it.

---

## 1. Where the public key has to land

The pin exists in **two** places, and the repository refuses to use a pin whose
two copies disagree (fail closed, `core/r1_approval.py::_mirror_matches`):

| place | what it carries | who may write it |
| --- | --- | --- |
| `core/r1_approval.py::PINNED_PUBLIC_KEY` | the source of truth: a tuple `(modulus, exponent)` of two integers | the maintainer, through an explicit instruction |
| `benchmarks/evidence/r1_approval_key.json` | the mirror for the audit trail: `{"public_key": {"n": "<base64>", "e": 65537}}` | the same, in the same change |

The format of the mirror is fixed by the repository itself - do not invent it.
`core/r1_approval.py::public_key_record` produces it:

```python
{
    "n": base64.b64encode(modulus.to_bytes((modulus.bit_length() + 7) // 8, "big")).decode("ascii"),
    "e": 65537,
}
```

`n` is the base64 of the **big-endian bytes of the modulus**, without a leading
zero byte and with the minimal length. The mirror is compared against the
source pin by decoding it again
(`int.from_bytes(base64.b64decode(value), "big")`), so any deviation in the
encoding - a hex string instead of base64, a truncated modulus, an inverted
byte order - is refused as a tampered pin rather than silently accepted.

---

## 2. Before you start

* An **offline** working directory **outside** the repository, e.g.
  `~/r1-approval-key/`. The private key must never be written into the working
  tree of the repository - not even into an untracked file, and not even
  "just to test it".
* `openssl` 1.1.1 or newer (`openssl version`). On Windows: the `openssl` binary
  of Git for Windows, or WSL.
* A place to store the passphrase of the private key. **Never** put the
  passphrase into a command line, a shell history, an environment variable or a
  `.env` file.

---

## 3. Step by step

### Step 1 - generate the key pair

RSA **4096** bits is the recommended size; RSA **2048** bits is the minimum
that this procedure accepts. The private key is encrypted with a passphrase at
generation time, so the file on disk is useless without it.

```bash
cd ~/r1-approval-key
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -aes256 -out r1_approval_private.pem
chmod 600 r1_approval_private.pem
ls -l r1_approval_private.pem
```

* `-aes256` encrypts the private key with a passphrase that you type
  interactively. If you drop it, the file is an unencrypted private key on
  disk - do not.
* `umask 077` and `chmod 600` keep the file unreadable for anyone else on the
  machine.
* The passphrase is yours alone. It is **not** stored in this repository and
  not in any password manager that the repository can read.

### Step 2 - read the public parameters

The public half is the modulus `n` and the exponent `e`. Two ways to obtain
them:

**(a) OpenSSL only** - no extra Python package needed:

```bash
openssl rsa -in r1_approval_private.pem -pubout -outform PEM -out r1_approval_public.pem
openssl rsa -in r1_approval_private.pem -noout -modulus
# Modulus=AAAB3NzaC1yc2EAAAADAQABAAABgQ...
```

The hex value behind `Modulus=` is `n`; the exponent of a freshly generated
OpenSSL RSA key is `65537`.

**(b) The helper of the repository** - preferred, because it uses the exact
encoding the mirror expects. Run it on your machine, from a checkout of the
repository, with the key **outside** the working tree:

```bash
cd /path/to/Agentic-security-RLVR
python - <<'PY'
import base64
from cryptography.hazmat.primitives import serialization
from core.r1_approval import public_key_record

path = str.home() + "/r1-approval-key/r1_approval_private.pem"
with open(path, "rb") as handle:
    key = serialization.load_pem_private_key(handle.read(), password=None)
numbers = key.public_key().public_numbers()
print(public_key_record((numbers.n, numbers.e)))
PY
```

The command prints **only** the public record:

```json
{"n": "AJ3l2...", "e": 65537}
```

Save that output as `record.json` in the same directory - it is the artefact of
step 3.

`cryptography` is not a dependency of this repository; install it in your own
environment (`pip install cryptography`) or use route (a). The script reads the
private key from a path **outside** the repository and prints nothing but the
public record - the private key is never written into the working tree.

> The snippets of this document are POSIX shell. On Windows, run them in WSL or
> in Git Bash - or translate them; the commands themselves are the same
> `openssl` ones.

### Step 3 - check the record against the key, locally

Before anything leaves your machine, verify that the record you are about to
hand over really is the public half of the key you just generated:

```bash
python - <<'PY'
import base64, json, subprocess

record = json.loads(open("record.json", encoding="utf-8").read())
modulus = int.from_bytes(base64.b64decode(record["n"]), "big")
assert record["e"] == 65537, record["e"]
assert modulus.bit_length() in (2048, 4096), modulus.bit_length()

public = subprocess.run(
    ["openssl", "rsa", "-in", "r1_approval_private.pem", "-pubout", "-outform", "DER"],
    capture_output=True, check=True,
).stdout
import hashlib
print("fingerprint of the public key (SHA-256):", hashlib.sha256(public).hexdigest())
print("modulus bits:", modulus.bit_length())
print("exponent:", record["e"])
PY
```

Keep the printed fingerprint: it is the **public** fingerprint of the approval
authority and it may - and should - appear in the audit trail of the change
that pins the key.

### Step 4 - hand over the public half only

Send the maintainer (or the agent that prepares the change) **only**:

* the record `{"n": "...", "e": 65537}`;
* the SHA-256 fingerprint of the public key;
* the key size and the date.

**Never** send, paste, commit or attach the private key, its passphrase, or a
file that contains either of them. If a private key ever reaches a chat, a
ticket, a CI log or a commit, treat the key as **burned**: generate a new pair
and pin that one instead.

### Step 5 - the repository side (only after an explicit permission)

Only after you have explicitly permitted it, the public half is written into the
two places of §1 - in **one** change, so that the source pin and its mirror
never disagree:

1. `core/r1_approval.py`:

   ```python
   PINNED_PUBLIC_KEY: Optional[Tuple[int, int]] = (
       int("<the decimal modulus>", 10),
       65537,
   )
   ```

2. `benchmarks/evidence/r1_approval_key.json`:

   ```json
   {
     "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
     "public_key": { "n": "<the base64 modulus>", "e": 65537 },
     "note": "<keep the note, updated for the pinned key>"
   }
   ```

3. Check that the pin is live:

   ```bash
   python -c "from core.r1_approval import pinned_public_key; print(pinned_public_key())"
   ```

   The result must be the tuple `(modulus, 65537)` and **not** `None`. A `None`
   means that the source pin and the mirror disagree - the mirror is then
   wrong, or the pin is not in the source at all.

### Step 6 - what changes in the state of the repository

Pinning a key is **not** an approval of a step. It changes two things that the
owner has to decide explicitly:

* **The tests of the R1 state change.** `tests/test_r1_dispatch_boundary.py`
  and `tests/test_r1_budget_ledger.py` used to assert that
  `core.r1_approval.PINNED_PUBLIC_KEY is None` - that was the proof that R1
  approves nothing. With a pinned key those assertions have to be replaced by
  the proof that the pin is the one you approved (the modulus, the exponent
  and the mirror that carries the same key), and the change of the R1 state has
  to be recorded as a deliberate step (R1 -> R2), not as a silent edit of a
  test. The **negative** proofs stay: a mirror that disagrees with the pin is
  refused, and a signature that does not verify is refused.
* **The rate card is a separate approval input.** `benchmarks/evidence/r1_rate_card.json`
  carries its own source and its own reading date, and its approval is the
  approval of the **rates** only: the owner approved the rates on 2026-11-15
  (`status: APPROVED`). Pinning the key does not approve the rate card, and the
  rate card is not changed by this procedure.

### Step 7 - the approval artifact itself (a later, separate act)

An approval artifact is signed **out of band** by you, with the private key, and
handed to the run as a file - it is never committed either. The signature is
RSASSA-PKCS1-v1_5 over SHA-256 of the canonical payload
(`json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)`
encoded as UTF-8), which is exactly what OpenSSL produces:

```bash
openssl dgst -sha256 -sign r1_approval_private.pem -out approval.sig approval_payload.json
```

The artifact carries the payload and the signature; the authority is the
signature, and the verification happens in the gate at dispatch time
(`benchmarks/r1_dispatch.py::DispatchGate._check_approval`). This procedure
does not create such an artifact and does not approve any step.

---

## 4. Hygiene rules

1. The private key stays on the machine of the approval authority, in a file
   with the permissions `600`, encrypted with a passphrase that only you know.
2. The private key never enters: the repository, a commit, a branch, a pull
   request, a CI job, an agent session, a chat, a ticket, a screenshot, a
   backup that is uploaded anywhere, or the process of the workflow.
3. Only `n`, `e` and the public fingerprint leave your machine.
4. The public fingerprint of the pinned key belongs in the audit trail of the
   change that pins it, next to the date and the size of the key.
5. `.gitignore` is not a security control: never rely on it to keep a private
   key out of the repository.

## 5. Rotation

A new key pair is a new approval authority:

1. generate a new pair (§3, steps 1-3);
2. pin the new public half in both places of §1 and record the new fingerprint;
3. re-approve every artifact that was signed with the old key - a signature of
   the old key is verified against the **new** pin and is therefore refused
   (`approval_not_verified`);
4. destroy the old private key.

Rotation does not have to be a rotation of the whole workflow: it can be a
rotation of the key alone. What it always entails is a re-approval of the
artifacts that the old key signed.

## 6. The checklist of the change that pins a key

- [ ] the key pair was generated on the machine of the owner, outside the repository;
- [ ] the private key is encrypted, has the permissions `600` and never left that machine;
- [ ] the public record is `{"n": "<base64 of the big-endian modulus>", "e": 65537}`;
- [ ] the size of the key is 2048 or 4096 bits and the fingerprint is recorded;
- [ ] `core/r1_approval.py::PINNED_PUBLIC_KEY` and `benchmarks/evidence/r1_approval_key.json` carry the **same** key;
- [ ] `pinned_public_key()` returns the tuple and not `None`;
- [ ] the tests of the R1 state (`PINNED_PUBLIC_KEY is None`) were replaced deliberately by the proof that the pin is the approved one, and the state change is recorded;
- [ ] `benchmarks/evidence/r1_rate_card.json` is not changed by this change (the rates carry the owner's own approval of 2026-11-15);
- [ ] no approval artifact was created, signed or committed by this change.
