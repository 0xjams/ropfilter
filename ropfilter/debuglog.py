# ropfilter/debuglog.py
from __future__ import annotations
import json, os, time, threading

class _NullLogger:
    def emit(self, *_args, **_kw): pass
    def close(self): pass

class DebugLog:
    """
    Minimal JSONL logger:
      - one JSON object per line
      - adds ts (unix float) and thread id
    """
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        # line-buffered
        self._fh = open(path, "a", buffering=1, encoding="utf-8")
        self._lock = threading.Lock()

    def emit(self, event: str, **fields):
        rec = {"ts": time.time(), "tid": threading.get_ident(), "event": event}
        rec.update(fields)
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            self._fh.write(line + "\n")

    def close(self):
        try:
            with self._lock:
                self._fh.flush()
                self._fh.close()
        except Exception:
            pass
