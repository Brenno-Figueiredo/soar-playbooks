"""Armazenamento (SQLite): execuções, passos, aprovações e a TRILHA DE AUDITORIA encadeada por hash.

Cada registro da auditoria carrega o hash do anterior: alterar, apagar ou inserir um registro no meio quebra a corrente e o 'verify' acusa.
Triggers impedem UPDATE e DELETE pelo próprio programa. Nada disso resiste a quem tem acesso ao arquivo e refaz a corrente inteira, ou a quem
apaga os ÚLTIMOS registros: para isso existe a âncora (o último hash, guardado FORA do banco) e, em produção, o envio dos registros a um sistema externo."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY AUTOINCREMENT, playbook TEXT NOT NULL, pb_hash TEXT NOT NULL, alert TEXT NOT NULL, alert_hash TEXT NOT NULL,
    mode TEXT NOT NULL, operator TEXT NOT NULL, state TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', created TEXT NOT NULL, updated TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS steps(run_id INTEGER NOT NULL, idx INTEGER NOT NULL, step_id TEXT NOT NULL, action TEXT NOT NULL, risk TEXT NOT NULL, state TEXT NOT NULL,
    params TEXT NOT NULL DEFAULT '{}', output TEXT NOT NULL DEFAULT '{}', undo TEXT, idem TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', PRIMARY KEY(run_id, idx));
CREATE TABLE IF NOT EXISTS approvals(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL, step_id TEXT NOT NULL, approver TEXT NOT NULL, decision TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, event TEXT NOT NULL, run_id INTEGER, step_id TEXT, data TEXT NOT NULL,
    prev TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'a trilha de auditoria não pode ser alterada'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'a trilha de auditoria não pode ser apagada'); END;
"""


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(seq: int, ts: str, actor: str, event: str, run_id: Optional[int], step_id: Optional[str], data: str, prev: str) -> str:
    payload = canonical({"seq": seq, "ts": ts, "actor": actor, "event": event, "run": run_id, "step": step_id, "data": data, "prev": prev})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def run_label(run_id: int) -> str:
    return f"R{run_id:04d}"


def parse_label(label: str) -> int:
    s = str(label).strip().upper()
    if not s.startswith("R") or not s[1:].isdigit():
        raise ValueError(f"identificador de execução inválido: {label!r} (esperado algo como R0003)")
    return int(s[1:])


class Store:
    def __init__(self, path: str):
        self.path = path
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def _q(self, sql: str, args: Tuple = ()) -> List[sqlite3.Row]:
        return self.db.execute(sql, args).fetchall()

    # ---- execuções -----------------------------------------------------------------------------------------------------------------
    def create_run(self, playbook: str, pb_hash: str, alert: Dict, alert_hash: str, mode: str, operator: str, state: str, note: str, now: str) -> int:
        cur = self.db.execute("INSERT INTO runs(playbook, pb_hash, alert, alert_hash, mode, operator, state, note, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?)",
                              (playbook, pb_hash, canonical(alert), alert_hash, mode, operator, state, note, now, now))
        self.db.commit()
        return int(cur.lastrowid)

    def get_run(self, run_id: int) -> Optional[Dict[str, Any]]:
        rows = self._q("SELECT * FROM runs WHERE id=?", (run_id,))
        return dict(rows[0]) if rows else None

    def set_run(self, run_id: int, state: str, note: Optional[str], now: str) -> None:
        if note is None:
            self.db.execute("UPDATE runs SET state=?, updated=? WHERE id=?", (state, now, run_id))
        else:
            self.db.execute("UPDATE runs SET state=?, note=?, updated=? WHERE id=?", (state, note, now, run_id))
        self.db.commit()

    def find_recent(self, playbook: str, alert_hash: str, mode: str, since: str) -> Optional[int]:
        rows = self._q("SELECT id FROM runs WHERE playbook=? AND alert_hash=? AND mode=? AND created>=? AND state NOT IN ('blocked','aborted') ORDER BY id DESC LIMIT 1", (playbook, alert_hash, mode, since))
        return int(rows[0]["id"]) if rows else None

    def list_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._q("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))]

    # ---- passos --------------------------------------------------------------------------------------------------------------------
    def add_steps(self, run_id: int, steps: List[Tuple[str, str, str]]) -> None:
        self.db.executemany("INSERT INTO steps(run_id, idx, step_id, action, risk, state) VALUES (?,?,?,?,?,'pending')", [(run_id, i, sid, act, risk) for i, (sid, act, risk) in enumerate(steps)])
        self.db.commit()

    def get_steps(self, run_id: int) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._q("SELECT * FROM steps WHERE run_id=? ORDER BY idx", (run_id,))]

    def set_step(self, run_id: int, idx: int, **fields: Any) -> None:
        cols = ", ".join(f"{k}=?" for k in fields)
        self.db.execute(f"UPDATE steps SET {cols} WHERE run_id=? AND idx=?", (*fields.values(), run_id, idx))
        self.db.commit()

    # ---- aprovações ----------------------------------------------------------------------------------------------------------------
    def add_approval(self, run_id: int, step_id: str, approver: str, decision: str, reason: str, now: str) -> None:
        self.db.execute("INSERT INTO approvals(run_id, step_id, approver, decision, reason, ts) VALUES (?,?,?,?,?,?)", (run_id, step_id, approver, decision, reason, now))
        self.db.commit()

    def approvals(self, run_id: int, step_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if step_id:
            return [dict(r) for r in self._q("SELECT * FROM approvals WHERE run_id=? AND step_id=? ORDER BY id", (run_id, step_id))]
        return [dict(r) for r in self._q("SELECT * FROM approvals WHERE run_id=? ORDER BY id", (run_id,))]

    # ---- auditoria -----------------------------------------------------------------------------------------------------------------
    def audit(self, actor: str, event: str, run_id: Optional[int], step_id: Optional[str], data: Dict[str, Any], now: str) -> int:
        last = self._q("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1")
        seq, prev = (last[0]["seq"] + 1, last[0]["hash"]) if last else (1, GENESIS)
        blob = canonical(data)
        self.db.execute("INSERT INTO audit(seq, ts, actor, event, run_id, step_id, data, prev, hash) VALUES (?,?,?,?,?,?,?,?,?)",
                        (seq, now, actor, event, run_id, step_id, blob, prev, entry_hash(seq, now, actor, event, run_id, step_id, blob, prev)))
        self.db.commit()
        return seq

    def audit_rows(self, run_id: Optional[int] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        sql, args = "SELECT * FROM audit" + (" WHERE run_id=?" if run_id is not None else "") + " ORDER BY seq", ((run_id,) if run_id is not None else ())
        rows = [dict(r) for r in self._q(sql, args)]
        return rows[-limit:] if limit else rows

    def count_events(self, event: str, since: str, action: Optional[str] = None) -> int:
        n = 0
        for r in self._q("SELECT data FROM audit WHERE event=? AND ts>=?", (event, since)):
            if action is None or json.loads(r["data"]).get("action") == action:
                n += 1
        return n

    def anchor(self) -> Dict[str, Any]:
        last = self._q("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1")
        return {"seq": last[0]["seq"], "hash": last[0]["hash"]} if last else {"seq": 0, "hash": GENESIS}

    def verify(self, anchor: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        prev, expected = GENESIS, 1
        rows = self._q("SELECT * FROM audit ORDER BY seq")
        for r in rows:
            if r["seq"] != expected:
                return False, f"registro {expected} ausente: a sequência pula para {r['seq']} (registro apagado)"
            if r["prev"] != prev:
                return False, f"o registro {r['seq']} não aponta para o anterior: a corrente foi quebrada"
            if entry_hash(r["seq"], r["ts"], r["actor"], r["event"], r["run_id"], r["step_id"], r["data"], r["prev"]) != r["hash"]:
                return False, f"o registro {r['seq']} foi ALTERADO: o conteúdo não bate com o hash"
            prev, expected = r["hash"], expected + 1
        if anchor is not None:
            if anchor.get("seq", 0) > len(rows):
                return False, f"a âncora é do registro {anchor['seq']}, mas a trilha só tem {len(rows)}: registros finais foram APAGADOS"
            if anchor.get("seq", 0) > 0 and rows[anchor["seq"] - 1]["hash"] != anchor.get("hash"):
                return False, f"o registro {anchor['seq']} não bate com a âncora: a trilha foi reescrita"
        return True, f"{len(rows)} registros íntegros" + (" e conferem com a âncora" if anchor is not None else " (sem âncora: não detecta o apagamento dos últimos registros)")
