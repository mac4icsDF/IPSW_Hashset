#!/usr/bin/env python3
"""Build a known-good hash database from an iOS IPSW file.

Usage:
  build_known_good_db.py --ipsw <file.ipsw> --key <key.pem> --db <output.db>
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import plistlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from typing import Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("build_known_good_db")

# ---------------------------------------------------------------------------
# SQLite schema
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS metadata (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ios_version     TEXT NOT NULL,
    build_number    TEXT NOT NULL,
    device_model    TEXT NOT NULL,
    ipsw_filename   TEXT NOT NULL,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ios_version, build_number, device_model, ipsw_filename)
);

CREATE TABLE IF NOT EXISTS dmgs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    metadata_id     INTEGER NOT NULL REFERENCES metadata(id),
    dmg_name        TEXT NOT NULL,
    dmg_type        TEXT,
    dmg_size        INTEGER NOT NULL,
    is_encrypted    INTEGER NOT NULL DEFAULT 1,
    UNIQUE(metadata_id, dmg_name)
);

CREATE TABLE IF NOT EXISTS files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    dmg_id          INTEGER NOT NULL REFERENCES dmgs(id),
    file_path       TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    md5             TEXT NOT NULL,
    file_size       INTEGER NOT NULL,
    UNIQUE(dmg_id, file_path)
);

CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_files_md5 ON files(md5);
CREATE INDEX IF NOT EXISTS idx_files_path ON files(file_path);
"""

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

KB = 1024
MB = 1024 * KB
GB = 1024 * MB

MANIFEST_TO_MOUNT = {
    "OS.Info":                "fs",
    "Cryptex1,SystemOS.Info": "sys",
    "Cryptex1,AppOS.Info":    "app",
    "RestoreRamDisk.Info":    "rdisk",
}


def _format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _validate_key(pem_path: str) -> None:
    if not os.path.isfile(pem_path):
        log.error("Key file not found: %s", pem_path)
        sys.exit(1)
    with open(pem_path, "r") as f:
        content = f.read()
    if "-----BEGIN PRIVATE KEY-----" not in content:
        log.error("Invalid PEM key file (no 'BEGIN PRIVATE KEY' header)")
        sys.exit(1)


def _hash_file(filepath: str) -> Tuple[str, str, int]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(64 * KB)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)
            size += len(chunk)
    return sha256.hexdigest(), md5.hexdigest(), size


def _create_pem_db(pem_path: str, aea_names: list[str], out_dir: str) -> str:
    """Create a pem-db JSON (base64-encoded PEM) for ipsw mount --pem-db."""
    with open(pem_path, "rb") as f:
        pem_b64 = base64.b64encode(f.read()).decode()
    db = {name: pem_b64 for name in aea_names}
    db_path = os.path.join(out_dir, "pem_db.json")
    with open(db_path, "w") as f:
        json.dump(db, f)
    return db_path


def _mount_via_ipsw(
    mount_type: str,
    ipsw_path: str,
    pem_db_path: str,
    mount_point: str,
    ident: Optional[str] = None,
) -> bool:
    """Mount a DMG type from an IPSW using ipsw mount --detach."""
    cmd = [
        "ipsw", "mount", mount_type, ipsw_path,
        "--detach", "--pem-db", pem_db_path,
        "-m", mount_point,
    ]
    if ident:
        cmd.extend(["--ident", ident])

    log.info("  Mounting '%s' …", mount_type)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

    if result.returncode != 0:
        log.error("  Mount failed: %s", result.stderr.strip() or result.stdout.strip())
        return False

    if not os.path.ismount(mount_point):
        log.error("  Mount point not mounted after ipsw mount")
        return False

    return True


def _unmount(mount_point: str) -> None:
    if sys.platform == "darwin":
        cmd = ["hdiutil", "detach", mount_point]
    else:
        cmd = ["umount", mount_point]
    log.info("  Unmounting …")
    subprocess.run(cmd, capture_output=True, timeout=60)


# ---------------------------------------------------------------------------
# filesystem walking & hashing
# ---------------------------------------------------------------------------


def _walk_and_hash(
    mount_point: str,
    dmg_id: int,
    cur: sqlite3.Cursor,
    stats: dict,
) -> None:
    mount_point = os.path.realpath(mount_point)
    prefix_len = len(mount_point.rstrip("/")) + 1

    batch: list[tuple] = []
    BATCH_SIZE = 1000
    count = 0

    for dirpath, dirnames, filenames in os.walk(mount_point):
        for name in filenames:
            full_path = os.path.join(dirpath, name)
            rel_path = full_path[prefix_len:]

            is_symlink = os.path.islink(full_path)
            if is_symlink:
                target = os.readlink(full_path)
                if target.startswith("/"):
                    candidate = os.path.normpath(
                        os.path.join(mount_point, target.lstrip("/"))
                    )
                else:
                    candidate = os.path.normpath(
                        os.path.join(os.path.dirname(full_path), target)
                    )
                if not os.path.exists(candidate) or not os.path.isfile(
                    os.path.realpath(candidate)
                ):
                    continue
                path_to_hash = os.path.realpath(candidate)
            else:
                path_to_hash = full_path

            try:
                sha, md5, size = _hash_file(path_to_hash)
            except (OSError, PermissionError) as e:
                log.debug("  Skipping %s (unreadable: %s)", rel_path, e)
                continue

            batch.append((dmg_id, rel_path, sha, md5, size))

            if len(batch) >= BATCH_SIZE:
                _flush_batch(cur, batch)
                batch.clear()
                stats["progress"] += BATCH_SIZE
            count += 1

    if batch:
        _flush_batch(cur, batch)
        stats["progress"] += len(batch)

    stats["total_files"] += count


INSERT_FILE_SQL = """
INSERT OR IGNORE INTO files
(dmg_id, file_path, sha256, md5, file_size)
VALUES (?, ?, ?, ?, ?)
"""


def _flush_batch(cur: sqlite3.Cursor, batch: list[tuple]) -> None:
    cur.executemany(INSERT_FILE_SQL, batch)


# ---------------------------------------------------------------------------
# BuildManifest parsing
# ---------------------------------------------------------------------------


def _parse_manifest(ipsw_path: str) -> dict:
    """Extract metadata + DMG-to-mount-type mapping from BuildManifest."""
    with zipfile.ZipFile(ipsw_path, "r") as z:
        with z.open("BuildManifest.plist") as f:
            manifest = plistlib.load(f)

    identities = manifest.get("BuildIdentities", [])
    if not identities:
        return {"error": "No BuildIdentities found"}

    bi = identities[0]
    info = bi.get("Info", {})

    mount_targets: list[tuple] = []
    seen: set[str] = set()

    for identity in identities:
        restore_behavior = identity.get("Info", {}).get("RestoreBehavior")
        _walk_manifest_for_mounts(
            identity.get("Manifest", {}), mount_targets, seen,
            restore_behavior=restore_behavior,
        )

    return {
        "ios_version": bi.get("Ap,ProductMarketingVersion", "") or info.get("BuildNumber", ""),
        "build_number": info.get("BuildNumber", ""),
        "device_model": bi.get("Ap,ProductType", ""),
        "mount_targets": mount_targets,
    }


def _walk_manifest_for_mounts(
    node: dict,
    out: list,
    seen: set[str],
    prefix: str = "",
    restore_behavior: Optional[str] = None,
) -> None:
    if not isinstance(node, dict):
        return
    if "Path" in node and prefix and prefix in MANIFEST_TO_MOUNT:
        path = node["Path"]
        if isinstance(path, str) and path not in seen:
            mount_type = MANIFEST_TO_MOUNT[prefix]
            ident = restore_behavior if mount_type == "rdisk" else None
            out.append((mount_type, ident, path))
            seen.add(path)
        return
    for key, val in node.items():
        fp = f"{prefix}.{key}" if prefix else key
        _walk_manifest_for_mounts(val, out, seen, fp, restore_behavior) if isinstance(val, dict) else None
        if isinstance(val, list):
            for item in val:
                _walk_manifest_for_mounts(item, out, seen, fp, restore_behavior)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a known-good hash database from an iOS IPSW."
    )
    parser.add_argument("--ipsw", required=True, help="Path to IPSW file")
    parser.add_argument("--key", required=True, help="Path to AEA PEM private key")
    parser.add_argument("--db", required=True, help="Path to output SQLite database")
    args = parser.parse_args()

    if not os.path.isfile(args.ipsw):
        log.error("IPSW file not found: %s", args.ipsw)
        sys.exit(1)

    _validate_key(args.key)
    pem_path = os.path.abspath(args.key)
    db_path = os.path.abspath(args.db)

    # ---- step 1: parse BuildManifest ----
    log.info("Parsing BuildManifest.plist …")
    meta = _parse_manifest(args.ipsw)
    if "error" in meta:
        log.error("Failed to parse BuildManifest: %s", meta["error"])
        sys.exit(1)

    ios_version = meta["ios_version"]
    build_number = meta["build_number"]
    device_model = meta["device_model"]
    mount_targets = meta["mount_targets"]
    log.info("  iOS %s (%s) – %s", ios_version, build_number, device_model)

    with zipfile.ZipFile(args.ipsw, "r") as z:
        all_entries = z.infolist()
    dmg_entries = {
        e.filename: e
        for e in all_entries
        if e.filename.endswith(".dmg") or e.filename.endswith(".dmg.aea")
    }

    # ---- step 2: initialise SQLite ----
    log.info("Initialising SQLite database …")
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=OFF")
    cur = conn.cursor()
    cur.executescript(SCHEMA_SQL)

    cur.execute(
        "INSERT OR IGNORE INTO metadata "
        "(ios_version, build_number, device_model, ipsw_filename) "
        "VALUES (?, ?, ?, ?)",
        (ios_version, build_number, device_model, os.path.basename(args.ipsw)),
    )
    cur.execute(
        "SELECT id FROM metadata "
        "WHERE ios_version=? AND build_number=? AND device_model=? AND ipsw_filename=?",
        (ios_version, build_number, device_model, os.path.basename(args.ipsw)),
    )
    metadata_id = cur.fetchone()[0]
    conn.commit()

    # ---- step 3: create pem-db JSON ----
    work_dir = tempfile.mkdtemp(prefix="ipsw_known_good_")
    log.info("Work directory: %s", work_dir)

    aea_names = [n for n in dmg_entries if n.endswith(".dmg.aea")]
    pem_db_path = _create_pem_db(pem_path, aea_names, work_dir)

    # ---- step 4: process each mount target ----
    dmgs_processed = 0
    dmgs_total = len(mount_targets)
    overall_stats = {"total_files": 0, "progress": 0}

    try:
        for idx, (mount_type, ident, dmg_path) in enumerate(mount_targets, 1):
            dmg_entry = dmg_entries.get(dmg_path)
            dmg_size = dmg_entry.file_size if dmg_entry else 0
            is_aea = dmg_path.endswith(".aea")

            log.info(
                "[%d/%d] %-6s  %s  (%s)",
                idx, dmgs_total,
                mount_type,
                dmg_path,
                _format_bytes(dmg_size),
            )

            mp = os.path.join(work_dir, mount_type)
            os.makedirs(mp, exist_ok=True)

            ok = _mount_via_ipsw(mount_type, args.ipsw, pem_db_path, mp, ident)
            if not ok:
                log.warning("  Skipping %s (mount failed)", mount_type)
                continue

            cur.execute(
                "INSERT OR IGNORE INTO dmgs "
                "(metadata_id, dmg_name, dmg_type, dmg_size, is_encrypted) "
                "VALUES (?, ?, ?, ?, ?)",
                (metadata_id, mount_type, f"ipsw:{dmg_path}", dmg_size, 1 if is_aea else 0),
            )
            cur.execute(
                "SELECT id FROM dmgs WHERE metadata_id=? AND dmg_name=?",
                (metadata_id, mount_type),
            )
            dmg_id = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM files WHERE dmg_id=?", (dmg_id,))
            if cur.fetchone()[0] > 0:
                log.info("  Already in DB, skipping")
                _unmount(mp)
                continue
            conn.commit()

            log.info("  Walking filesystem …")
            _walk_and_hash(mp, dmg_id, cur, overall_stats)

            _unmount(mp)

            dmgs_processed += 1
            conn.commit()
            log.info("  Done – %d files", overall_stats["total_files"])

    except KeyboardInterrupt:
        log.warning("Interrupted – cleaning up …")
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
        log.info("Removed work directory")

    # ---- final stats ----
    cur.execute("SELECT COUNT(*) FROM files")
    total = cur.fetchone()[0]
    conn.commit()
    conn.close()

    log.info("=" * 50)
    log.info("Database written to: %s", db_path)
    log.info("  Total entries:    %d", total)
    log.info("  DMGs processed:   %d / %d", dmgs_processed, dmgs_total)
    log.info("=" * 50)


if __name__ == "__main__":
    main()
