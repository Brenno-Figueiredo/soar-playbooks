"""O MUNDO SIMULADO: um arquivo JSON com bloqueios, contas, hosts, reputação de IPs, chamados e avisos. É o único lugar onde as ações deixam marca.
Nenhuma ação toca a rede, o sistema operacional ou qualquer outra máquina."""
from __future__ import annotations

import copy
import json
import os
import tempfile
from typing import Any, Dict

MAX_WORLD = 5 * 1024 * 1024
SECTIONS: Dict[str, type] = {"blocklist": dict, "directory": dict, "hosts": dict, "intel": dict, "tickets": list, "notifications": list, "applied_keys": dict}


class WorldError(ValueError):
    pass


def empty_world() -> Dict[str, Any]:
    return {k: t() for k, t in SECTIONS.items()}


def default_world() -> Dict[str, Any]:
    """Um ambiente fictício para a demonstração. Endereços de documentação (RFC 5737) são os 'atacantes'."""
    w = empty_world()
    w["directory"] = {"ana": {"privileged": False, "active": True, "sessions": 2, "department": "financeiro"},
                      "deploy": {"privileged": True, "active": True, "sessions": 3, "department": "engenharia"},
                      "admin": {"privileged": True, "active": True, "sessions": 1, "department": "ti"},
                      "break-glass": {"privileged": True, "active": True, "sessions": 0, "department": "ti"},
                      "svc-backup": {"privileged": True, "active": True, "sessions": 0, "department": "ti"}}
    w["hosts"] = {"PC-FIN-01": {"criticality": "medium", "isolated": False}, "PC-VENDAS-07": {"criticality": "low", "isolated": False},
                  "SRV-APP-01": {"criticality": "high", "isolated": False}, "DC-01": {"criticality": "critical", "isolated": False}}
    w["intel"] = {"203.0.113.50": {"score": 92, "tags": ["ssh-bruteforce"]}, "198.51.100.23": {"score": 85, "tags": ["scanner"]}, "192.0.2.99": {"score": 55, "tags": ["suspicious"]}}
    return w


def validate_world(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise WorldError("o mundo simulado deve ser um objeto JSON")
    unknown = set(data) - set(SECTIONS)
    if unknown:
        raise WorldError(f"seção desconhecida no mundo simulado: {', '.join(sorted(unknown))}")
    world = empty_world()
    for key, value in data.items():
        if not isinstance(value, SECTIONS[key]):
            raise WorldError(f"'{key}' deve ser {'um objeto' if SECTIONS[key] is dict else 'uma lista'}")
        world[key] = value
    for name, entry in world["directory"].items():
        if not isinstance(entry, dict) or not isinstance(entry.get("active", True), bool):
            raise WorldError(f"usuário '{name}' mal formado")
    for name, entry in world["hosts"].items():
        if not isinstance(entry, dict) or entry.get("criticality", "low") not in ("low", "medium", "high", "critical"):
            raise WorldError(f"host '{name}' mal formado (criticality: low, medium, high ou critical)")
    return world


def load_world(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        raise WorldError(f"não encontrei o mundo simulado '{path}' (crie com: world init)")
    if os.path.getsize(path) > MAX_WORLD:
        raise WorldError("mundo simulado grande demais (limite de 5 MB)")
    try:
        with open(path, encoding="utf-8-sig") as f:
            return validate_world(json.load(f))
    except json.JSONDecodeError as exc:
        raise WorldError(f"JSON inválido no mundo simulado: {exc}") from None


def save_world(path: str, world: Dict[str, Any]) -> None:
    """Grava por inteiro ou não grava: escreve num arquivo temporário e troca. Uma queda no meio não deixa o mundo pela metade."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".world-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(world, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def clone(world: Dict[str, Any]) -> Dict[str, Any]:
    return copy.deepcopy(world)
