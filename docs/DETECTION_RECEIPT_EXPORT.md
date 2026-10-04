# Exporting a detection receipt

`scripts/export_detection_receipt.py` writes a small redacted export for one
explicit local detection receipt. It reads only the path supplied by the caller
and uses the caller's existing file permissions.

```sh
python scripts/export_detection_receipt.py \
  --input ./detection-receipt.json \
  --expected-event-id 0123456789abcdef01234567 \
  --output ./detection-receipt-export.json
```

PowerShell (single line):

```powershell
python scripts/export_detection_receipt.py --input .\detection-receipt.json --expected-event-id 0123456789abcdef01234567 --output .\detection-receipt-export.json
```

## Copyable synthetic redaction example

From the repository root, the following command exports the committed
documentation fixture [examples/detection-receipt.synthetic.json](../examples/detection-receipt.synthetic.json)
without running a workload or contacting a service:

```sh
python scripts/export_detection_receipt.py \
  --input ./examples/detection-receipt.synthetic.json \
  --expected-event-id 0123456789abcdef01234567 \
  --output ./detection-receipt.synthetic-export.json
```

PowerShell (single line):

```powershell
python scripts/export_detection_receipt.py --input .\examples\detection-receipt.synthetic.json --expected-event-id 0123456789abcdef01234567 --output .\detection-receipt.synthetic-export.json
```

The fixture filename and its top-level banner identify it as synthetic-only.
Its `CONTAINMENT_FAILED` recorded result, timestamp, event/source identities,
and sensitive-field values are fabricated; no workload or source event was
executed or observed, and no execution or containment occurred. The output
path must be new: `./detection-receipt.synthetic-export.json` is an example
output only and is not committed. This offline command needs no `sudo`, native
workload, credentials, or service. The exporter output is at most 8 KiB,
includes `source_sha256` (the exact input-byte SHA-256) and the event ID, and reports
`NOT_AUTHENTICATED` and `NOT_PERFORMED`. Its redaction path omits the fixture's
observed PID/UID/argv, model, executable, workload/cgroup, runtime,
correlation, capture, and raw-error canaries. The synthetic identities and
recorded result are not evidence of actual execution, containment, native
safety, independent use, or adoption.

The expected event ID must be 24 lowercase hexadecimal characters and match the
receipt. The output path must be new, and its existing parent directories must
be ordinary directories without symbolic links or Windows reparse points. After
receipt validation and output-size checks succeed, an existing ordinary regular
output is reported on stderr as `OUTPUT_ALREADY_EXISTS`; choose a new output
filename. This is a failure exit, and the existing bytes and temporary-file
inventory are left unchanged. Invalid receipts, directories, links, reparse
points, unsafe parents, and raced or other filesystem errors retain the generic
failure diagnostic. The input must be a regular file without linked parent
components. The exporter
rejects input larger than 1 MiB, output larger than 8 KiB, versions longer than
64 characters, duplicate JSON keys at any depth, nesting deeper than 64 levels,
nonfinite numbers, unsupported receipt kinds, and inconsistent termination
evidence. Its diagnostics do not echo supplied paths, IDs, or parser and
operating-system errors.

The output allowlist contains the event and source identities, catalogue and
detector identity, recorded timestamp and result, and the SHA-256 of the exact
input bytes. A `TERMINATED` result also includes the recorded empty-state
evidence. It is accepted only when the primitive is
`pidfd-stop+cgroup.kill`, the recorded root populated count is integer `0`, the
surviving PID list is empty, the monotonic times are ordered, and the recorded
trigger-to-empty duration agrees with those times. A `CONTAINMENT_FAILED`
result remains a failure; its raw error is omitted and no empty-state evidence
is emitted.

Process IDs, user IDs, arguments, executable names, model and runtime details,
workload and cgroup paths, correlation data, capture details, and raw errors
are never copied into the export. The output is published without replacing an
existing path; the destination filesystem must support hard links. File
creation follows the caller's normal umask or Windows ACL. The exporter does
not change permissions, request elevation, contact a service, or alter the
receipt.

This is a redacted view of recorded data, not an authenticated receipt. The
source hash links the export to the bytes read but does not establish who made
them, whether the source commit or policy was active, or whether the recorded
event occurred. `NOT_PERFORMED` means the exporter does not inspect a live
workload or verify containment now. Even accepted empty-state evidence says
only that the receipt recorded the specified empty state at its recorded point.
The tool does not establish live safety, native qualification, or independent
use. Filesystem checks reduce accidental link and overwrite hazards; an actor
with the same permissions may still race parent path components between checks
and filesystem operations.
