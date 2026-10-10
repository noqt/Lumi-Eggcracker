# Support

Lumi Eggcracker is a free, open-source public alpha without a paid support
subscription or guaranteed response window. The existing free Q&A, bug-report
and private security-report routes require no purchase or sales call. Any
optional one-off assistance is separate: a nonbinding proposal, not currently
available to purchase. Interest in that proposal does not change access to or
handling of free support.

- Ask questions and share observed results from an actual supported-path run in
  [Q&A](https://github.com/noqt/Lumi-Eggcracker/discussions/categories/q-a).
- Report reproducible, non-security defects with the
  [bug form](https://github.com/noqt/Lumi-Eggcracker/issues/new?template=bug_report.yml).
- Report security-sensitive findings through
  [private vulnerability reporting](https://github.com/noqt/Lumi-Eggcracker/security/advisories/new).

Include the exact release or commit and a redacted description of the Linux
host. Never post credentials, private model files, raw process arguments or
environments. Read [LIMITATIONS.md](LIMITATIONS.md) before assuming a local-AI
runtime or deployment model is supported.

## Prepare a local receipt handoff

After building and installing a source revision that contains this change, a
local redacted projection can be prepared for an existing route:

```sh
eggcracker prepare-kill-receipt-handoff ./kill-receipt.json \
  --route q-and-a --output ./handoff.json
```

Use `q-and-a`, `bug-report`, or `private-security` only as the intended
destination. The route selection is not permission or authorization to submit;
follow the existing route guidance above. The projection does not authenticate
the receipt, establish anonymity or privacy-safety, prove independent
containment, or certify that it is safe to share. Review it as an operator
before any sharing. This option is available only in a source/build containing
this change and is not a claim that the published v1.0.10 release includes it.
