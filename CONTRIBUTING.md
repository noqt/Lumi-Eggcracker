# Contributing to Lumi Eggcracker

Lumi Eggcracker is a destructive, privileged Linux public alpha. Contributions
are welcome, but a convenient detector or passing fixture is not enough to make
new containment claims.

## Choose the right route

- Use [Q&A](https://github.com/noqt/Lumi-Eggcracker/discussions/categories/q-a)
  for questions and observed feedback from an actual supported-path run.
- Use the [bug form](https://github.com/noqt/Lumi-Eggcracker/issues/new?template=bug_report.yml)
  for reproducible, non-security defects.
- Use [private vulnerability reporting](https://github.com/noqt/Lumi-Eggcracker/security/advisories/new)
  for an approval bypass, containment escape, false successful receipt,
  privilege issue, unsafe installer behaviour or other security-sensitive
  finding. Do not publish exploit details first.

Keep public Q&A to questions and observed feedback from an actual
supported-path run. Coordinate any large code change through separately
authorised maintainer review; do not use public support routes for
product-direction proposals.

## Local checks

Use Python 3.11 or newer. The ordinary unit suite does not grant permission to
run native root or containment tests on your workstation.

```sh
python -m pip install jsonschema==4.26.0 ruff==0.16.1 PyYAML==6.0.3
ruff check src tests scripts
PYTHONPATH=src python -m unittest discover -s tests -v
```

For packaging changes, also build and verify the release material:

```sh
python scripts/build_release.py --output dist/github
python scripts/verify_release.py \
  --artifact dist/github/lumi-eggcracker-0.5.0.pyz \
  --source-archive dist/github/lumi-eggcracker-0.5.0-source.zip \
  --release-bundle dist/github/lumi-eggcracker-0.5.0-linux.zip
```

Any detector, profile, approval, installer, watchdog, containment or receipt
change also requires the exact native gates in [QUALIFICATION.md](QUALIFICATION.md)
on a disposable supported Linux environment whose loss is acceptable. A
Windows pass or GitHub Actions run cannot substitute for native qualification.

## Product and evidence boundaries

Direct `cgroup.kill` plus exact empty proof remains authoritative. Do not add or
claim unsupported backends, universal AI recognition, behavioural detection,
network or credential isolation, malware prevention, EDR functions, or
container/cloud coverage without a separately qualified release boundary.

Keep fixtures synthetic and reports redacted. Never commit credentials, private
model data, machine-specific paths, raw process arguments or environments.
Preserve existing package, CLI, service, socket, policy, receipt, schema and
release identifiers unless a reviewed compatibility plan says otherwise.

## Pull requests

Keep each pull request focused. State the exact user-visible change, tests run,
platform and Python version, relevant skips, destructive-test boundary, and any
documentation or compatibility impact. New behaviour needs positive, negative
and failure-path tests. By submitting a contribution, you agree that it is
provided under this repository's [Apache-2.0 licence](LICENSE).
