# Try Lumi Eggcracker without installing it

You can test Eggcracker's kill mechanism on a disposable GitHub machine. You
don't need Linux, a GPU, a model download or a local installation.

![Four-step hosted-proof path: fork, run, see what survives, and share the public run](docs/hosted-proof-flow.svg)

## Start it with GitHub CLI

If you already use the authenticated [GitHub CLI](https://cli.github.com/), a
fail-closed helper can create or reuse only your exact Lumi Eggcracker fork,
enable the reviewed workflow and dispatch it. On macOS or Linux, copy and paste
this block to make a temporary shallow checkout and start the helper without
navigating the repository or Actions UI:

```sh
proof_dir="$(mktemp -d)/Lumi-Eggcracker" &&
gh repo clone noqt/Lumi-Eggcracker "$proof_dir" -- --depth=1 &&
python3 "$proof_dir/scripts/start_hosted_proof.py" \
  --i-understand-this-kills-a-test-tree \
  --wait
```

On Windows PowerShell, use the equivalent block:

```powershell
$proofDir = Join-Path ([IO.Path]::GetTempPath()) (
  "Lumi-Eggcracker-" + [guid]::NewGuid().ToString("N")
)
gh repo clone noqt/Lumi-Eggcracker $proofDir -- --depth=1
if ($LASTEXITCODE -ne 0) { throw "Clone failed" }
python (Join-Path $proofDir "scripts\start_hosted_proof.py") `
  --i-understand-this-kills-a-test-tree `
  --wait
```

The helper prints the exact workflow-run URL when GitHub returns it directly or
the helper can uniquely correlate it to this dispatch. With `--wait`, it follows
that exact run through completion and ends with an explicit `PASS` or `FAIL` and
the exact run URL. Successful runs stay concise; add `--show-log` when you also
want the bounded public workflow log in the terminal. Failed runs print that log
automatically for diagnosis. If exact correlation is unavailable, it does not
guess; it leaves the fork's workflow page for manual inspection. Without
`--wait`, it prints separate copyable watch and log commands. The run URL remains
available for the same result in GitHub's interface.

### Or use the GitHub interface

1. [Fork Lumi Eggcracker](https://github.com/noqt/Lumi-Eggcracker/fork).
2. In your fork, open **Actions** and enable workflows if GitHub asks.
3. Open **Containment probe (manual disposable runner)**, choose **Run
   workflow**, tick the acknowledgement and run it on the default branch.

The temporary source checkout remains at the printed operating-system temp
location after the run. If you already have a current public source checkout,
run the helper directly instead:

```sh
python3 scripts/start_hosted_proof.py \
  --i-understand-this-kills-a-test-tree \
  --wait
```

The acknowledgement is mandatory. The helper refuses a same-named repository
that is not a fork of `noqt/Lumi-Eggcracker`. The helper itself never executes
through a shell; the copy-paste setup above uses your shell only to create the
temporary public-source checkout and start the helper.
It also refuses to dispatch if the fork's workflow differs from the reviewed
workflow. If an existing fork is simply stale, rerun the helper with
`--sync-fork` to explicitly permit a fast-forward-only GitHub sync from the
exact upstream. The helper never adds `--force`: after syncing, it revalidates
the fork identity, default branch and reviewed workflow blob, and dispatches
nothing if any check fails. It never requests or prints a token; authenticated
`gh` handles its own credentials. If the bounded run lookup is unavailable or
ambiguous, it prints the fork's workflow page instead. This starts the same
disposable hosted proof described above; it does not install Eggcracker or test
workload recognition.

The proof creates a harmless two-process test tree, kills it with Eggcracker's
containment mechanism and checks that an unrelated canary survives. A passing
run prints a JSON receipt with `"result":"TERMINATED"`,
`"target_survivors":0` and `"canary_survived":true`, followed by
`FORK_PROBE_RESULT=PASS`.

Automations can validate that current PASS receipt, or a redacted refusal or
failure receipt, against the versioned [hosted-proof receipt v1 schema](schemas/hosted-proof-receipt-v1.schema.json).
The [synthetic success example](schemas/examples/hosted-proof-receipt-v1-success.json)
is a copy-ready shape for integration tests; its all-zero source identities are
placeholders and must never be treated as evidence of a run.
Schema validation checks structure only. It does not authenticate the run,
source commit or tree, workflow or host, and it does not claim that the host is
suitable for production or that Eggcracker detected a real workload. The v1
file remains compatible; an incompatible contract uses a new versioned path.

If you save the single JSON receipt object as `receipt.json`, the repository's
zero-dependency validator gives automation an exact local exit status without
uploading or echoing the receipt:

```sh
python3 scripts/validate_hosted_proof_receipt.py receipt.json
```

Exit status `0` means the object matches exactly one current v1 shape; status
`1` means it does not. This validates structure only and does not turn a
synthetic example into run evidence or authenticate a real receipt.

A partner repository can call the same local validator as a pinned composite
action:

```yaml
- uses: noqt/Lumi-Eggcracker/actions/validate-hosted-proof-receipt@<40-character-commit-sha>
  with:
    receipt: receipt.json
```

Replace the placeholder with an immutable commit containing the action. The
receipt path is passed as an environment value rather than interpolated into a
shell command. The action uploads nothing and prints only the bounded validator
result; it still validates structure rather than authenticating a run.

For a complete read-only job, a partner repository can instead call the reusable
workflow with the same local receipt path:

```yaml
jobs:
  validate-eggcracker-receipt:
    uses: noqt/Lumi-Eggcracker/.github/workflows/validate-hosted-proof-receipt.yml@<40-character-commit-sha>
    with:
      receipt: receipt.json
```

Pin the workflow to an immutable commit containing it. The job checks out the
caller repository with persisted credentials disabled, then invokes the pinned
local validator action. It requests read-only contents permission, exposes no
outputs or secrets and uploads no receipt.

If it passes, returns a redacted failure or gives you confusing friction,
[send the public run](https://github.com/noqt/Lumi-Eggcracker/issues/new?template=hosted_probe_result.yml).
The short form asks for the workflow URL and what happened. That is useful
evidence either way.

NOQT will acknowledge a complete public hosted-proof report within two
Australian business days. That acknowledgement is not a promise of a fix,
release, private support, or product qualification.

This hosted proof tests only the bounded kill mechanism. It does not install
Eggcracker, recognise an AI workload or prove the whole product. The workflow
is designed for GitHub's disposable Ubuntu 24.04 runner; don't adapt it to a
self-hosted machine.

[Read how Eggcracker works and where its current boundary sits](README.md).
