# Hugging Face distribution

The public Space at <https://huggingface.co/spaces/noqt/eggcracker> is a
generated distribution mirror of GitHub `main`. GitHub remains the canonical
source and release authority. The Space is not a hosted Eggcracker runtime.

## Synchronisation contract

- `huggingface-sync-policy.json` is the machine-readable mapping.
- `scripts/build_huggingface_surface.py` copies tracked product files, excludes
  Git and GitHub-only control paths, and applies the reviewed Space metadata and
  static page.
- Every snapshot contains `HUGGINGFACE_SYNC.json` with the exact GitHub commit
  and `HUGGINGFACE_MANIFEST.json` with content hashes.
- `.github/workflows/sync-huggingface.yml` runs after every push to `main`, on
  manual dispatch, and daily to repair out-of-band drift. It performs a true
  mirror and verifies remote checksums after upload.
- Direct changes on Hugging Face are unsupported and will be overwritten.

The workflow requires a fine-grained Hugging Face write token scoped only to
`noqt/eggcracker`, stored in the GitHub Actions secret `HF_TOKEN`. Never put the
token in source, workflow arguments, generated files, or logs.

## Local candidate build

Use a fresh output directory and an exact 40-character source commit:

```sh
python scripts/build_huggingface_surface.py \
  --source-root . \
  --output /safe/task-temp/huggingface-surface \
  --source-revision "$GITHUB_SHA"
```

The output is a review candidate only. Publication still follows repository
authority, independent review, and the protected GitHub workflow.
