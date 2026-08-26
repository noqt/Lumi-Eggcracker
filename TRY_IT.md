# Try Lumi Eggcracker without installing it

You can test Eggcracker's kill mechanism on a disposable GitHub machine. You
don't need Linux, a GPU, a model download or a local installation.

![Four-step hosted-proof path: fork, run, see what survives, and share the public run](docs/hosted-proof-flow.svg)

1. [Fork Lumi Eggcracker](https://github.com/noqt/Lumi-Eggcracker/fork).
2. In your fork, open **Actions** and enable workflows if GitHub asks.
3. Open **Containment probe (manual disposable runner)**, choose **Run
   workflow**, tick the acknowledgement and run it on the default branch.

The proof creates a harmless two-process test tree, kills it with Eggcracker's
containment mechanism and checks that an unrelated canary survives. A passing
run prints a JSON receipt with `"result":"TERMINATED"`,
`"target_survivors":0` and `"canary_survived":true`, followed by
`FORK_PROBE_RESULT=PASS`.

If it passes, refuses safely or gives you confusing friction, [send the public
run](https://github.com/noqt/Lumi-Eggcracker/issues/new?template=hosted_probe_result.yml).
The short form asks for the workflow URL and what happened. That is useful
evidence either way.

This hosted proof tests only the bounded kill mechanism. It does not install
Eggcracker, recognise an AI workload or prove the whole product. The workflow
is designed for GitHub's disposable Ubuntu 24.04 runner; don't adapt it to a
self-hosted machine.

[Read how Eggcracker works and where its current boundary sits](README.md).
