# Releasing

The public repository is authoritative for verifier source, protocol specs,
vectors, and public rules data. Private OpenSlay builds pin an exact public
commit and must pass their separate engine/server/Godot compatibility suite
before the game ships that verifier.

## Release checklist

1. Update `__version__` and `CHANGELOG.md`.
2. Run `python tools/release_gate.py --mode ci` and `python -m pytest -q`.
3. Install the release extra and build twice from clean Git archives:
   `python -m pip install -e ".[release]"` then
   `python tools/build_release.py dist`.
4. Audit and install the artifacts with
   `python tools/verify_artifacts.py dist`.
5. Test the candidate public commit against the pinned private integration.
6. Create a signed annotated tag whose name exactly matches the package version,
   for example `git tag -s v0.2.1`.
7. Push only the public tag. The release workflow rebuilds and retests the tag,
   attests the artifacts, creates a draft release with every asset, and then
   publishes it.

All `0.x` versions are marked as GitHub prereleases. A `v1+` release is blocked
while the bundled descriptor filename/id/allow-list flag identify it as partial.
Tags and published release assets must never be moved or replaced. Enable the
repository's `main` and `v*` rulesets, read-only default Actions token, private
vulnerability reporting, and immutable releases before the first tag.

PyPI publishing is deliberately absent from the bootstrap workflow. If it is
added later, use a separately protected environment and Trusted Publishing;
never store a long-lived PyPI token in this repository.
