"""`redsim evidence-pack` and `redsim evidence`: evidence for auditors and reviewers.

`evidence-pack --out DIR` writes the compliance pack (audit chains, controls
crosswalk, system summary, hashed manifest). With `--run RUN_ID` it writes the
signed per-run evidence pack instead: `<out>/redsim-evidence-<run>.zip`.

`evidence verify PATH.zip [--public-key PEM]` re-checks a per-run pack offline
and exits 0 only when every check holds. `evidence keygen --out DIR` writes a
fresh Ed25519 keypair for the API to sign with.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from redsim.cli import _console

if TYPE_CHECKING:
    import argparse

    from redsim.config import RedsimConfig

PRIVATE_KEY_NAME = "evidence-signing-key.pem"
PUBLIC_KEY_NAME = "evidence-signing-key.pub.pem"


def cmd_evidence_pack(args: argparse.Namespace, config: RedsimConfig) -> None:
    """Generate a compliance evidence pack at ``--out``, or one run's signed pack with ``--run``."""
    out_dir = getattr(args, "out", None)
    if not out_dir:
        _console._err("evidence-pack requires --out DIR")
        sys.exit(2)

    run_id = getattr(args, "run", None)
    if run_id:
        _run_pack(str(run_id), Path(out_dir), config)
        return

    from redsim.services.evidence import generate_evidence_pack

    project = getattr(args, "project", None)
    manifest = generate_evidence_pack(out_dir, config=config, project=project)

    # Per-chain verify_chain() verdicts live in verification.json; here we
    # just report the chain count alongside the file count + overall hash.
    _console._info(f"Evidence pack written to {manifest.out_dir}")
    _console._info(f"Redsim version: {manifest.redsim_version}")
    _console._info(f"Audit chains exported: {len(manifest.chains)}")
    _console._info(f"Files in pack: {len(manifest.files)}")
    _console._info(f"Overall pack hash (sha256): {manifest.pack_hash}")
    sys.exit(0)


def _run_pack(run_id: str, out_dir: Path, config: RedsimConfig) -> None:
    """Build one run's signed pack through the configured database and blob store."""
    from redsim.services.evidence_pack import build_run_evidence_pack, load_evidence_signer

    if not os.environ.get("REDSIM_DB_URL"):
        _console._err("evidence-pack --run needs REDSIM_DB_URL (the run record lives in the database)")
        sys.exit(2)
    from redsim.db.session import get_session

    try:
        signer = load_evidence_signer()
    except (OSError, TypeError, ValueError) as exc:
        _console._err(f"the configured evidence signing key could not be read ({exc.__class__.__name__})")
        sys.exit(2)
    try:
        with get_session() as sess:
            pack = build_run_evidence_pack(sess, run_id, config=config, signer=signer)
    except LookupError as exc:
        _console._err(str(exc))
        sys.exit(1)
    except ValueError as exc:
        _console._err(f"digest mismatch: {exc}")
        sys.exit(1)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / pack.filename
    path.write_bytes(pack.zip_bytes)
    _console._info(f"Evidence pack written to {path}")
    _console._info(f"Run: {pack.run_id}  project: {pack.project_id}")
    _console._info(f"Reports included: {', '.join(pack.manifest['reports']['included']) or 'none'}")
    _console._info(f"Audit chain: {pack.manifest['chain']['count']} events, "
                   f"verified={pack.manifest['chain']['verified']}")
    _console._info(f"Pack hash (sha256): {pack.pack_hash}")
    if pack.signed:
        _console._info(f"Signed: ed25519 key {pack.key_id}")
    else:
        _console._warn("Unsigned: no evidence signing key is configured")
    sys.exit(0)


def cmd_evidence_verify(args: argparse.Namespace, config: RedsimConfig) -> None:
    """Verify one pack offline; exit 0 when every check holds, 1 otherwise."""
    from redsim.services.evidence_pack import verify_evidence_pack

    path = Path(args.path)
    if not path.exists():
        _console._err(f"no such file: {path}")
        sys.exit(2)
    trusted = None
    if getattr(args, "public_key", None):
        trusted = Path(args.public_key).read_text(encoding="utf-8")
    result = verify_evidence_pack(path, trusted_public_key_pem=trusted)

    def line(name: str, value: object) -> None:
        mark = "ok  " if value is True else ("skip" if value is None else "FAIL")
        _console._info(f"  {mark}  {name}")

    _console._info(f"Evidence pack {path.name}  run={result.run_id}  format={result.format}")
    line("file digests match the manifest", result.files_match)
    line("pack hash matches the file digests", result.pack_hash_matches)
    line("run record matches its recorded digest", result.record_digest_matches)
    line(f"audit chain verified ({result.chain_count} events)", result.chain_verified)
    line("signature present", result.signature_present)
    line(f"signature valid (ed25519 key {result.key_id or '-'})", result.signature_valid)
    line("signed by the trusted key", result.trusted_key_matches)
    for problem in result.problems:
        _console._warn(f"  problem: {problem}")
    if result.ok:
        _console._info("VERIFIED")
        sys.exit(0)
    _console._err("NOT VERIFIED")
    sys.exit(1)


def cmd_evidence_keygen(args: argparse.Namespace, config: RedsimConfig) -> None:
    """Write a fresh Ed25519 keypair; refuse to overwrite an existing key."""
    from redsim.services.evidence_pack import KEY_FILE_ENV, generate_keypair

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    private_path = out_dir / PRIVATE_KEY_NAME
    public_path = out_dir / PUBLIC_KEY_NAME
    if private_path.exists() or public_path.exists():
        _console._err(f"refusing to overwrite an existing key under {out_dir}")
        sys.exit(1)
    private_pem, public_pem, key_id = generate_keypair()
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(private_pem)
    public_path.write_bytes(public_pem)
    _console._info(f"Private key: {private_path} (mode 0600, keep it on the API host only)")
    _console._info(f"Public key:  {public_path} (share it with whoever verifies packs)")
    _console._info(f"Key id:      {key_id}")
    _console._info(f"Configure the API with {KEY_FILE_ENV}={private_path}")
    sys.exit(0)
