# ropfilter/cache_sqlite.py  — v0.2.21
from __future__ import annotations
import os, sqlite3, pickle, gzip, hashlib, time
from typing import List, Optional, Tuple
from .parsing import parse_file
from .models import Gadget

# bump when parse/classify semantics change
PARSE_SCHEMA_VER = "parse-v3"   # safe to bump later if needed

def _default_cache_path() -> str:
    # ~/.cache/ropfilter/parse_cache.sqlite  (Linux/macOS)
    # %LOCALAPPDATA%\ropfilter\parse_cache.sqlite  (Windows)
    root = os.environ.get("LOCALAPPDATA") if os.name == "nt" else os.path.join(os.path.expanduser("~"), ".cache")
    path = os.path.join(root, "ropfilter")
    os.makedirs(path, exist_ok=True)
    return os.path.join(path, "parse_cache.sqlite")

def _connect(db_path: Optional[str] = None) -> sqlite3.Connection:
    db = sqlite3.connect(db_path or _default_cache_path())
    db.execute("""
        CREATE TABLE IF NOT EXISTS parses (
            file_path   TEXT NOT NULL,
            mtime       INTEGER NOT NULL,
            size        INTEGER NOT NULL,
            exact_reg   INTEGER NOT NULL,
            schema_ver  TEXT NOT NULL,
            args_hash   TEXT NOT NULL,
            blob        BLOB NOT NULL,
            PRIMARY KEY (file_path, mtime, size, exact_reg, schema_ver, args_hash)
        )
    """)
    db.execute("PRAGMA journal_mode=WAL;")
    db.execute("PRAGMA synchronous=NORMAL;")
    return db

def _stat_key(path: str) -> Tuple[int,int]:
    st = os.stat(path)
    return int(st.st_mtime), int(st.st_size)

def _args_hash(extra: dict) -> str:
    # stable hash of relevant knobs; keep small to avoid surprises
    h = hashlib.sha256()
    # preserve order by sorting keys
    for k in sorted(extra.keys()):
        v = extra[k]
        h.update(str(k).encode())
        h.update(b"=")
        h.update(str(v).encode())
        h.update(b";")
    return h.hexdigest()[:16]

def _dump_gadgets(gs: List[Gadget]) -> bytes:
    return gzip.compress(pickle.dumps(gs, protocol=pickle.HIGHEST_PROTOCOL))

def _load_gadgets(blob: bytes) -> List[Gadget]:
    return pickle.loads(gzip.decompress(blob))

def parse_file_cached(path: str, *, exact_reg: bool, extra_args: Optional[dict] = None, db_path: Optional[str] = None) -> List[Gadget]:
    """
    Cache wrapper around parsing.parse_file().
    - Keyed by (file_path, mtime, size, exact_reg, PARSE_SCHEMA_VER, args_hash)
    - extra_args: include only params that affect parsing/classification (e.g., banned patterns version if you ever externalize them)
    """
    extra_args = extra_args or {}
    mtime, size = _stat_key(path)
    ah = _args_hash(extra_args)
    db = _connect(db_path)

    row = db.execute(
        "SELECT blob FROM parses WHERE file_path=? AND mtime=? AND size=? AND exact_reg=? AND schema_ver=? AND args_hash=?",
        (path, mtime, size, 1 if exact_reg else 0, PARSE_SCHEMA_VER, ah)
    ).fetchone()

    if row:
        try:
            return _load_gadgets(row[0])
        except Exception:
            # fall through to re-parse on any deserialization error
            pass

    # cache miss → parse fresh
    gadgets = parse_file(path)

    # store
    blob = _dump_gadgets(gadgets)
    db.execute(
        "INSERT OR REPLACE INTO parses(file_path, mtime, size, exact_reg, schema_ver, args_hash, blob) VALUES (?,?,?,?,?,?,?)",
        (path, mtime, size, 1 if exact_reg else 0, PARSE_SCHEMA_VER, ah, blob)
    )
    db.commit()
    return gadgets
