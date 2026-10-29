"""Figures régénérées par script à partir de metrics.json."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

BLEU = "#1f5fa8"


def _style() -> None:
    plt.rcParams.update({"font.family": "sans-serif", "axes.spines.top": False, "axes.spines.right": False,
                         "figure.dpi": 130, "axes.grid": True, "grid.alpha": 0.25})


def tracer(m: dict, dossier: Path) -> None:
    dossier.mkdir(parents=True, exist_ok=True)
    _style()
    confs = [(k, l) for k, l in (("sans_llm", "sans modèle"), ("tres_petit", "qwen3:0.6b"), ("petit", "qwen3:4b")) if k in m]
    if confs:
        fig, ax = plt.subplots(figsize=(5.8, 3.6))
        vals = [m[k]["taux_acceptation_legitimes_pct"] for k, _ in confs]
        ax.bar([l for _, l in confs], [v["moyenne"] for v in vals], yerr=[v["ecart_type"] for v in vals], color=BLEU, capsize=4)
        ax.set_ylabel("demandes légitimes acceptées (%)"); ax.set_ylim(0, 105)
        for i, (k, _) in enumerate(confs):
            ax.text(i, 3, f"illégitimes émis : {m[k]['illegitimes_emis_total']}", ha="center", color="white", fontsize=8)
        fig.tight_layout(); fig.savefig(dossier / "acceptation_par_configuration.png"); plt.close(fig)
        base = m[confs[0][0]]["taux_refus_par_categorie_pct"]
        cats = [c for c in base if base[c]["moyenne"] is not None]
        fig, ax = plt.subplots(figsize=(6.4, 3.8))
        w = 0.8 / len(confs)
        for j, (k, l) in enumerate(confs):
            ax.barh([i + j * w for i in range(len(cats))], [m[k]["taux_refus_par_categorie_pct"][c]["moyenne"] or 0 for c in cats],
                    height=w, label=l)
        ax.set_yticks([i + w * (len(confs) - 1) / 2 for i in range(len(cats))])
        ax.set_yticklabels(cats, fontsize=8)
        ax.set_xlabel("demandes illégitimes refusées (%)"); ax.legend(fontsize=8)
        fig.tight_layout(); fig.savefig(dossier / "refus_par_categorie.png"); plt.close(fig)
    e = m.get("experiences")
    if e:
        t = e["ocsp"]["crl"]["taille_par_nombre_de_revoques"]
        fig, ax = plt.subplots(figsize=(5.4, 3.4))
        ax.plot([int(k) for k in t], [v["der_octets"] / 1024 for v in t.values()], marker="o", color=BLEU)
        ax.set_xscale("log"); ax.set_yscale("log")
        ax.set_xlabel("certificats révoqués"); ax.set_ylabel("taille de la CRL (Ko, DER)")
        fig.tight_layout(); fig.savefig(dossier / "taille_crl.png"); plt.close(fig)
        et = {k: v for k, v in e["compromission"]["etapes_s"].items() if k != "total_s"}
        fig, ax = plt.subplots(figsize=(6.2, 3.4))
        ax.barh([k[2:].replace("_s", "").replace("_", " ") for k in et], list(et.values()), color=BLEU)
        ax.invert_yaxis(); ax.set_xlabel("durée (s)"); ax.tick_params(axis="y", labelsize=7)
        fig.tight_layout(); fig.savefig(dossier / "compromission_etapes.png"); plt.close(fig)
