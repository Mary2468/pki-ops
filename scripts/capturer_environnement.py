"""Écrit results/ENVIRONMENT.json : machine, versions logicielles, modèles Ollama (digests) et empreintes des données.

Les valeurs sont lues sur la machine qui exécute le script ; rien n'est saisi à la main.
"""

from __future__ import annotations

import hashlib
import importlib.metadata as md
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

import httpx
import psutil
import yaml

RACINE = Path(__file__).resolve().parents[1]


def sha256(chemin: Path) -> str:
    h = hashlib.sha256()
    h.update(chemin.read_bytes())
    return h.hexdigest()


def commande(*args: str) -> str | None:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=20).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def main() -> None:
    cfg = yaml.safe_load((RACINE / "config" / "experiment.yaml").read_text(encoding="utf-8"))
    hote = cfg["ollama"]["hote"]
    ollama: dict = {"hote": hote, "joignable": False}
    try:
        ollama["version"] = httpx.get(f"{hote}/api/version", timeout=5).json().get("version")
        tags = httpx.get(f"{hote}/api/tags", timeout=5).json().get("models", [])
        ollama["modeles_installes"] = {m["name"]: "sha256:" + m["digest"] for m in tags}
        ollama["joignable"] = True
    except (httpx.HTTPError, ValueError):
        pass
    attendus = {k: v["digest"] for k, v in cfg["modeles"].items()}
    ollama["digests_conformes_a_la_config"] = {
        cfg["modeles"][k]["etiquette"]: ollama.get("modeles_installes", {}).get(cfg["modeles"][k]["etiquette"]) == d
        for k, d in attendus.items()}
    paquets = sorted(d.metadata["Name"] for d in md.distributions())
    donnees = {str(p.relative_to(RACINE)).replace("\\", "/"): sha256(p) for p in sorted((RACINE / "data").glob("*.jsonl"))}
    cpu = platform.processor() or None
    env = {
        "systeme": {"os": platform.platform(), "machine": platform.machine(), "cpu": cpu,
                    "coeurs_logiques": psutil.cpu_count(), "ram_totale_go": round(psutil.virtual_memory().total / 2**30, 1),
                    "gpu": "aucun utilisé (CPU seul)"},
        "python": sys.version.split()[0],
        "uv": commande("uv", "--version"),
        "git": commande("git", "--version"),
        "commit": commande("git", "-C", str(RACINE), "rev-parse", "HEAD"),
        "ollama": ollama,
        "paquets": {p: md.version(p) for p in paquets if p.lower() in {
            "cryptography", "pydantic", "pyyaml", "httpx", "psutil", "pytest", "matplotlib"}},
        "empreintes_donnees": donnees,
        "graine": cfg["graine"], "temperature": cfg["temperature"], "contexte": cfg["contexte"],
    }
    sortie = RACINE / os.environ.get("PKIOPS_RESULTATS", "results") / "ENVIRONMENT.json"
    sortie.parent.mkdir(parents=True, exist_ok=True)
    sortie.write_text(json.dumps(env, indent=1, ensure_ascii=False), encoding="utf-8", newline="\n")
    print(f"écrit {sortie.relative_to(RACINE)}")


if __name__ == "__main__":
    main()
