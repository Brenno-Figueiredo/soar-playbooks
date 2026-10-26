"""Política de segurança: os limites que NENHUM playbook consegue contornar. É a diferença entre automação e acidente."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Tuple

DEFAULT_PROTECTED = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
                     "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "::/128")
MUTATING_ACTIONS = ("block_ip", "disable_account", "isolate_host", "revoke_sessions")
RISKS = ("low", "medium", "high")


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    automation_enabled: bool = True                       # a chave de desligamento: False impede QUALQUER ação que altere algo
    approval_required_for: Tuple[str, ...] = ("medium", "high")
    two_person_for: Tuple[str, ...] = ("high",)           # dois aprovadores diferentes, nenhum deles quem iniciou a execução
    protected_nets: Tuple[str, ...] = DEFAULT_PROTECTED
    protected_accounts: Tuple[str, ...] = ("break-glass", "svc-backup")
    protected_hosts: Tuple[str, ...] = ("DC-01",)
    max_block_prefix_v4: int = 24                         # não bloqueia redes maiores que /24
    max_block_prefix_v6: int = 64
    block_hours_max: int = 720
    isolate_critical: bool = False                        # isolar um ativo crítico é decisão humana, fora do playbook
    rate_limit_per_hour: Dict[str, int] = field(default_factory=lambda: {"block_ip": 20, "disable_account": 5, "isolate_host": 3, "revoke_sessions": 10})
    max_steps_per_run: int = 20
    dedupe_hours: int = 6                                 # o mesmo alerta, pelo mesmo playbook, não abre outra execução nesta janela

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        if not isinstance(data, dict):
            raise PolicyError("a política deve ser um objeto JSON")
        known = {f.name for f in fields(cls)}
        pol = cls()
        for key, value in data.items():
            if key not in known:
                raise PolicyError(f"opção desconhecida: '{key}'")
            default = getattr(pol, key)
            if isinstance(default, bool):
                if not isinstance(value, bool):
                    raise PolicyError(f"'{key}' deve ser true ou false")
            elif isinstance(default, int):
                if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                    raise PolicyError(f"'{key}' deve ser um inteiro positivo")
            elif isinstance(default, tuple):
                if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
                    raise PolicyError(f"'{key}' deve ser uma lista de textos")
                value = tuple(value)
            elif isinstance(default, dict):
                if (not isinstance(value, dict) or set(value) - set(MUTATING_ACTIONS)
                        or any(isinstance(v, bool) or not isinstance(v, int) or v <= 0 for v in value.values())):
                    raise PolicyError(f"'{key}' deve mapear ações ({', '.join(MUTATING_ACTIONS)}) para inteiros positivos")
                value = {**default, **value}
            setattr(pol, key, value)
        pol.validate()
        return pol

    def validate(self) -> None:
        for key in ("approval_required_for", "two_person_for"):
            if set(getattr(self, key)) - set(RISKS):
                raise PolicyError(f"'{key}' só aceita: {', '.join(RISKS)} (ações só de leitura nunca pedem aprovação)")
        if set(self.two_person_for) - set(self.approval_required_for):
            raise PolicyError("'two_person_for' precisa estar contido em 'approval_required_for': não dá para pedir duas pessoas onde ninguém é pedida")
        for n in self.protected_nets:
            try:
                ipaddress.ip_network(n, strict=True)
            except ValueError:
                raise PolicyError(f"rede protegida inválida: '{n}'") from None
        if not 8 <= self.max_block_prefix_v4 <= 32 or not 32 <= self.max_block_prefix_v6 <= 128:
            raise PolicyError("prefixos máximos fora do intervalo (IPv4: 8 a 32, IPv6: 32 a 128)")
        if self.block_hours_max > 24 * 365:
            raise PolicyError("'block_hours_max' maior que um ano")

    def networks(self) -> List[Any]:
        return [ipaddress.ip_network(n) for n in self.protected_nets]

    def is_protected_net(self, net) -> bool:
        return any(net.version == p.version and net.overlaps(p) for p in self.networks())

    def is_protected_account(self, user: str) -> bool:
        return user.lower() in {a.lower() for a in self.protected_accounts}

    def is_protected_host(self, host: str) -> bool:
        return host.lower() in {h.lower() for h in self.protected_hosts}


def defaults_dict() -> Dict[str, Any]:
    from dataclasses import asdict
    return {k: (list(v) if isinstance(v, tuple) else v) for k, v in asdict(Policy()).items()}


def load_policy(path: str) -> Policy:
    try:
        with open(path, encoding="utf-8-sig") as f:
            return Policy.from_dict(json.load(f))
    except json.JSONDecodeError as exc:
        raise PolicyError(f"JSON inválido na política: {exc}") from None
