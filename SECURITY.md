# Security policy

Please do not disclose suspected verifier vulnerabilities in a public issue.
Use GitHub's private vulnerability-reporting form for this repository:

https://github.com/CA7AX/OpenSlay-VF/security/advisories/new

Include the affected package and protocol versions, a minimal synthetic
transcript or vector, the expected result, and the observed result. Do not
attach real player transcripts, witness files, client nonces, credentials, or
private OpenSlay source.

The verifier checks transcript consistency under the assumptions documented in
`SPEC.md`. A successful result is not a certification of entropy, server
honesty, rules correctness, match completion, or overall game fairness.
