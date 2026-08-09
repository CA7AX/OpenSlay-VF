# Contributing

Contributions to the public protocol, verifier, documentation, and test vectors
are welcome.

1. Create a branch and keep each change focused.
2. Install the project with `python -m pip install -e ".[test]"`.
3. Run `python tools/release_gate.py --mode ci` and `python -m pytest -q`.
4. Update both English and Chinese specifications when protocol wording changes.
5. Add new immutable vectors beside existing vectors; never rewrite a released
   protocol's canonical encoding or expected outputs in place.

The public repository must remain independent of the private OpenSlay game
engine. Do not add imports of `openslay`, `openslay_server`, or `game_mode`, and
do not submit real match transcripts, witness sidecars, credentials, local
paths, proprietary assets, or private build material.

Changes to canonical bytes, digest inputs, accepted transcript structure,
random-operation semantics, or domain-separation tags require a new protocol or
algorithm version. Ordinary verifier fixes that preserve the protocol use the
package version only.
