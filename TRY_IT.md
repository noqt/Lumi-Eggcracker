# Try Lumi Eggcracker without installing it

You can test Eggcracker's kill mechanism on a disposable GitHub machine. You
don't need Linux, a GPU, a model download or a local installation.

![Four-step hosted-proof path: fork, run, see what survives, and share the public run](docs/hosted-proof-flow.svg)

1. [Fork Lumi Eggcracker](https://github.com/noqt/Lumi-Eggcracker/fork).
2. In your fork, open **Actions** and enable workflows if GitHub asks.
3. Open **Containment probe (manual disposable runner)**, choose **Run
   workflow**, tick the acknowledgement and run it on the default branch.

### Use the guided GitHub CLI path

If you already use the authenticated [GitHub CLI](https://cli.github.com/), a
fail-closed helper can create or reuse only your exact Lumi Eggcracker fork,
enable the reviewed workflow and dispatch it. On macOS or Linux, copy and paste
this block to make a temporary shallow checkout and start the helper without
navigating the repository or Actions UI:

```sh
proof_dir="$(mktemp -d)/Lumi-Eggcracker" &&
gh repo clone noqt/Lumi-Eggcracker "$proof_dir" -- --depth=1 &&
python3 "$proof_dir/scripts/start_hosted_proof.py" \
  --i-understand-this-kills-a-test-tree
```

The temporary source checkout remains at the printed operating-system temp
location after the run. If you already have a current public source checkout,
run the helper directly instead:

```sh
python3 scripts/start_hosted_proof.py \
  --i-understand-this-kills-a-test-tree
```

The acknowledgement is mandatory. The helper refuses a same-named repository
that is not a fork of `noqt/Lumi-Eggcracker`. The helper itself never executes
through a shell; the copy-paste setup above uses your shell only to create the
temporary public-source checkout and start the helper.
It also refuses to dispatch if the fork's workflow differs from the reviewed
workflow. It never requests or prints a token; authenticated `gh` handles its
own credentials. The helper prints the exact workflow-run URL when GitHub
returns it directly or the helper can uniquely correlate it to this dispatch.
If that bounded lookup is unavailable or ambiguous, it prints the fork's
workflow page instead. This starts the same disposable hosted proof described
above; it does not install Eggcracker or test workload recognition.

The proof creates a harmless two-process test tree, kills it with Eggcracker's
containment mechanism and checks that an unrelated canary survives. A passing
run prints a JSON receipt with `"result":"TERMINATED"`,
`"target_survivors":0` and `"canary_survived":true`, followed by
`FORK_PROBE_RESULT=PASS`.

Automations can validate that current PASS receipt, or a redacted refusal or
failure receipt, against the versioned [hosted-proof receipt v1 schema](schemas/hosted-proof-receipt-v1.schema.json).
Schema validation checks structure only. It does not authenticate the run,
source commit or tree, workflow or host, and it does not claim that the host is
suitable for production or that Eggcracker detected a real workload. The v1
file remains compatible; an incompatible contract uses a new versioned path.

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
