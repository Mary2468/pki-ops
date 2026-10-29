"""Génère site/index.html à partir de results/metrics.json (aucune valeur saisie à la main)."""

from __future__ import annotations

import html
import json
import os
import shutil
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
RESULTATS = RACINE / os.environ.get("PKIOPS_RESULTATS", "results")
SITE = RACINE / ("site" if RESULTATS.name == "results" else RESULTATS.name + "_site")
CONFS = (("sans_llm", "Sans modèle"), ("tres_petit", "qwen3:0.6b"), ("petit", "qwen3:4b"))


def f(x, nd=1) -> str:
    if x is None:
        return "—"
    return f"{x:.{nd}f}".replace(".", ",") if isinstance(x, float) else str(x)


def ms(d: dict) -> str:
    return f"{f(d['moyenne'])} ± {f(d['ecart_type'])}" if d["moyenne"] is not None else "—"


def tableau(entetes: list[str], lignes: list[list[str]]) -> str:
    h = "".join(f"<th>{html.escape(e)}</th>" for e in entetes)
    b = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in l) + "</tr>" for l in lignes)
    return f"<div class='tbl'><table><thead><tr>{h}</tr></thead><tbody>{b}</tbody></table></div>"


def section(titre: str, corps: str, cle: str) -> str:
    return f"<section id='{cle}'><h2>{html.escape(titre)}</h2>{corps}</section>"


def kpi(label: str, valeur: str, cle: str) -> str:
    return (f"<div class='kpi'><div class='v'>{valeur}</div><div class='l'>{html.escape(label)}</div>"
            f"<div class='k'>{html.escape(cle)}</div></div>")


def img(nom: str, alt: str) -> str:
    return f"<p class='fig'><img src='figures/{nom}' alt='{html.escape(alt)}'></p>"


def construire(m: dict, env: dict | None) -> str:
    kpis, sections = [], []
    if "sans_llm" in m:
        b = m["sans_llm"]
        kpis.append(kpi("certificats illégitimes émis (60 demandes, sans modèle)", str(b["illegitimes_emis_total"]), "sans_llm.illegitimes_emis_total"))
        kpis.append(kpi("demandes légitimes acceptées (sans modèle)", f(b["taux_acceptation_legitimes_pct"]["moyenne"]) + " %",
                        "sans_llm.taux_acceptation_legitimes_pct"))
    for cle, lab in CONFS[1:]:
        if cle in m:
            kpis.append(kpi(f"illégitimes émis avec {lab}", str(m[cle]["illegitimes_emis_total"]), f"{cle}.illegitimes_emis_total"))
    confs = [(k, l) for k, l in CONFS if k in m]
    if confs:
        lignes = [[l, str(m[k]["demandes_par_repetition"]), str(m[k]["repetitions"]), ms(m[k]["taux_acceptation_legitimes_pct"]) + " %",
                   str(m[k]["illegitimes_emis_total"]), f(m[k]["temps_moyen_par_demande_s"]["moyenne"], 2) + " s",
                   f(m[k]["appels_llm_par_demande"], 1)] for k, l in confs]
        corps = tableau(["Configuration", "Demandes", "Répétitions", "Légitimes acceptées (moy. ± éc.-type)",
                         "Illégitimes émis", "Temps moyen", "Appels de modèle par demande"], lignes)
        corps += img("acceptation_par_configuration.png", "Acceptation par configuration")
        sections.append(section("Campagne de demandes et ablation", corps, "campagne"))
        cats = [c for c, v in m[confs[0][0]]["taux_refus_par_categorie_pct"].items() if v["moyenne"] is not None]
        lignes = [[c] + [ms(m[k]["taux_refus_par_categorie_pct"][c]) + " %" for k, _ in confs] for c in cats]
        corps = tableau(["Catégorie de demande illégitime"] + [l for _, l in confs], lignes) + img("refus_par_categorie.png", "Refus par catégorie")
        sections.append(section("Refus par type de demande illégitime", corps, "refus"))
    e = m.get("experiences")
    if e:
        mt, oc = e["mtls"], e["ocsp"]
        lignes = [["mTLS : appels acceptés avant révocation", f"{mt['acceptes_avant']} sur 2"],
                  ["mTLS : appels refusés après révocation du pair", f"{mt['refuses_apres']} sur 2"],
                  ["OCSP : délai de la révocation au statut « revoked »", f(oc["ocsp"]["delai_revocation_a_statut_revoque_ms"]) + " ms"],
                  ["OCSP : taille d'une réponse", f"{oc['ocsp']['taille_reponse_octets']} octets"],
                  ["CRL : taille pour 1 / 10 / 100 / 1000 révoqués",
                   " / ".join(f"{v['der_octets']} o" for v in oc["crl"]["taille_par_nombre_de_revoques"].values())],
                  ["Renouvellement : cas corrects", f"{e['renouvellement']['cas_corrects']} sur {e['renouvellement']['cas_total']}"],
                  ["Compromission : durée totale de l'exercice", f(e["compromission"]["etapes_s"]["total_s"], 2) + f" s pour {e['compromission']['feuilles']} certificats"],
                  ["Compromission : anciennes feuilles encore valides / nouvelles valides",
                   f"{e['compromission']['anciennes_encore_valides']} / {e['compromission']['nouvelles_valides']}"],
                  ["Name Constraints : certificats hors domaine émis de force, refusés par le client",
                   f"{e['name_constraints']['hors_domaine_refuses_par_le_client']} sur {e['name_constraints']['hors_domaine_total']}"],
                  ["Registre signé : modifications détectées", f"{e['registre']['detectees']['modification']} sur {e['registre']['essais_par_type']}"],
                  ["Registre signé : suppressions détectées", f"{e['registre']['detectees']['suppression']} sur {e['registre']['essais_par_type']}"],
                  ["Alertes d'expiration justes", f(e["expirations"]["justesse_pct"]) + " %"]]
        corps = tableau(["Expérience", "Résultat"], lignes) + img("taille_crl.png", "Taille de la CRL") + img("compromission_etapes.png", "Étapes de la compromission")
        sections.append(section("Exigences complémentaires", corps, "experiences"))
        mn = e.get("menaces")
        if mn:
            lignes = [["Contrôleur trompé, code qui fait foi : illégitimes émis", f"{mn['controleur_trompe_avec_autorite_du_code']['illegitimes_emis']} sur {mn['illegitimes']}"],
                      ["Système naïf (avis du modèle suffisant) : illégitimes émis", f"{mn['sans_autorite_du_code']['illegitimes_emis']} sur {mn['illegitimes']}"],
                      ["… dont acceptés ensuite par un client TLS", str(mn["sans_autorite_du_code"]["acceptes_ensuite_par_un_client_tls"])],
                      ["Appel d'outil halluciné : appels refusés / illégitimes émis", f"{mn['outil_hallucine']['appels_refuses']} / {mn['outil_hallucine']['illegitimes_emis']}"],
                      ["Limite : Guichet trompé sur l'identité, illégitimes émis", f"{mn['guichet_usurpe']['illegitimes_emis']} sur {mn['illegitimes']}"]]
            sections.append(section("Modèle de menace : contre-mesures évaluées", tableau(["Vecteur", "Résultat"], lignes), "menaces"))
    pied = ""
    if env:
        pied = (f"<p class='meta'>Mesures sur {html.escape(env['systeme']['os'])}, {env['systeme']['coeurs_logiques']} cœurs, "
                f"{env['systeme']['ram_totale_go']} Go de RAM, sans GPU ; Python {html.escape(env['python'])} ; Ollama "
                f"{html.escape(str(env['ollama'].get('version')))} ; commit <code>{html.escape(str(env.get('commit'))[:10])}</code>.</p>")
    return PAGE.replace("{{KPIS}}", "".join(kpis)).replace("{{SECTIONS}}", "".join(sections)).replace("{{PIED}}", pied)


PAGE = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PKI-Ops : résultats</title>
<style>
:root{--bg:#f6f8fb;--fg:#17212b;--mu:#566472;--ac:#1f5fa8;--li:#dde4ec;--card:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#10151b;--fg:#e6ebf0;--mu:#97a3b0;--ac:#7db0e8;--li:#26303a;--card:#171e26}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,'Segoe UI',Arial,sans-serif}
main{max-width:940px;margin:0 auto;padding:40px 16px 64px}
h1,h2{color:var(--ac)}h1{font-size:2rem;margin:0 0 4px}h2{font-size:1.25rem;margin:40px 0 12px;border-bottom:1px solid var(--li);padding-bottom:6px}
.sub{color:var(--mu);margin:0 0 28px}.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin:24px 0}
.kpi{background:var(--card);border:1px solid var(--li);border-radius:8px;padding:14px 16px}.kpi .v{font-size:1.7rem;font-weight:600;color:var(--ac)}
.kpi .l{font-size:.9rem}.kpi .k{font-size:.75rem;color:var(--mu);font-family:ui-monospace,monospace;margin-top:4px}
.tbl{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.93rem}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--li)}
th{color:var(--mu);font-size:.82rem;text-transform:uppercase;letter-spacing:.03em}
.fig img{max-width:100%;height:auto;background:#fff;border-radius:6px;border:1px solid var(--li)}.meta{color:var(--mu);font-size:.85rem;margin-top:40px}
a{color:var(--ac)}code{font-family:ui-monospace,monospace;font-size:.9em}
</style></head><body><main>
<h1>PKI-Ops</h1>
<p class="sub">Autorité intermédiaire opérée par des agents encadrés. Page générée par <code>site/generer_site.py</code> depuis <code>results/metrics.json</code>.</p>
<div class="kpis">{{KPIS}}</div>
{{SECTIONS}}
{{PIED}}
<p class="meta"><a href="https://github.com/Mary2468/pki-ops">Code source et données</a></p>
</main></body></html>
"""


def main() -> None:
    m = json.loads((RESULTATS / "metrics.json").read_text(encoding="utf-8"))
    env_chemin = RESULTATS / "ENVIRONMENT.json"
    env = json.loads(env_chemin.read_text(encoding="utf-8")) if env_chemin.exists() else None
    (SITE / "figures").mkdir(parents=True, exist_ok=True)
    for p in (RESULTATS / "figures").glob("*.png"):
        shutil.copy(p, SITE / "figures" / p.name)
    (SITE / "index.html").write_text(construire(m, env), encoding="utf-8", newline="\n")
    print(f"{SITE.name}/index.html écrit")


if __name__ == "__main__":
    main()
