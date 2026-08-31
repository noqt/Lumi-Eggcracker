# Security policy

Lumi Eggcracker is a privileged local process-containment public alpha. Test
only workloads and disposable machines you own or are authorised to administer.

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/noqt/Lumi-Eggcracker/security/advisories/new).
Do not open a public issue first for an approval bypass, supported-profile
containment escape, false successful empty receipt, control-plane privilege
gain, self-protection defeat, unsafe installer or uninstall behaviour, or a
destructive false positive.

Include the affected release or exact commit, Linux/kernel/systemd versions,
impact, minimal reproduction, expected result and observed result. Redact
credentials, private model material, machine-specific paths, raw process
arguments and environments. A private report does not require a complete fix.

There is no public bug bounty or guaranteed response window. Please allow a
private assessment before publishing security details. Non-security defects
can use the repository's [bug form](https://github.com/noqt/Lumi-Eggcracker/issues/new?template=bug_report.yml).

## Supported scope

Security handling covers the published release line and the current 1.0.1
release-candidate branch only for the exact candidate identity under review.
Historical tags may be useful for comparison but do not receive new
qualification claims.

The exact boundary and non-claims are documented in
[SECURITY_MODEL.md](SECURITY_MODEL.md), [LIMITATIONS.md](LIMITATIONS.md), and
[QUALIFICATION.md](QUALIFICATION.md).
