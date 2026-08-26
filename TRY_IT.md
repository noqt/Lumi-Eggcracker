# Try Lumi Eggcracker without installing it

You can test Eggcracker's kill mechanism on a disposable GitHub machine. You
don't need Linux, a GPU, a model download or a local installation.

1. [Fork Lumi Eggcracker](https://github.com/noqt/Lumi-Eggcracker/fork).
2. In your fork, open **Actions** and enable workflows if GitHub asks.
3. Open **Containment probe (manual disposable runner)**, choose **Run
   workflow**, tick the acknowledgement and run it on the default branch.

The proof creates a harmless two-process test tree, kills it with Eggcracker's
containment mechanism and checks that an unrelated canary survives. A passing
run ends with `result: PASS`, `target_survivors: 0` and `outside_canary_alive:
true`.

If it passes, refuses safely or gives you confusing friction, [send the redacted
result](https://github.com/noqt/Lumi-Eggcracker/issues/new?template=first_kill_result.yml).
That is useful evidence either way.

This hosted proof tests only the bounded kill mechanism. It does not install
Eggcracker, recognise an AI workload or prove the whole product. The workflow
is designed for GitHub's disposable Ubuntu 24.04 runner; don't adapt it to a
self-hosted machine.

[Read how Eggcracker works and where its current boundary sits](README.md).
