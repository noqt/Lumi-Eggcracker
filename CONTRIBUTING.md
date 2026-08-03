# Contributing

Lumi Nutcracker is intentionally narrow. Changes should preserve the supported release claim and keep direct cgroup containment as the first trigger-side effect.

## Local checks

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
ruff check src tests scripts
python3 scripts/build_release.py --output dist
python3 scripts/verify_release.py \
  --artifact dist/lumi-nutcracker-0.1.0.pyz \
  --source-archive dist/lumi-nutcracker-0.1.0-source.zip \
  --release-bundle dist/lumi-nutcracker-0.1.0-linux.zip
```

Native tests create and terminate root-owned systemd cgroups. Run them only inside a disposable Linux VM you own, and never modify them to target pre-existing processes or cgroups.

Open an issue before adding a new containment backend, network isolation, AI identification, behavioural models or a broader security claim.
