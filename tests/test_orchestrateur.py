"""Orchestrateur de PKI-Ops : campagne sans modèle, faux client LLM scripté, pannes injectées."""

import json
import time

import pytest

from conftest import RACINE_DEPOT
from pki_ops import donnees
from pki_ops.journal import lire_journal
from pki_ops.llm import ErreurLLM, Reponse
from pki_ops.orchestrateur import Orchestrateur
from pki_ops.outils.autorite import charger_laboratoire
from pki_ops.outils.ceremonie import ceremonie

DEMANDES = donnees.lire(RACINE_DEPOT / "data" / "demandes.jsonl")
PAR_ID = {d["id"]: d for d in DEMANDES}


@pytest.fixture()
def lab(tmp_path):
    ceremonie(tmp_path / "pki", b"mot-de-passe-de-test", True, ["lab.internal"])
    return charger_laboratoire(tmp_path / "pki", RACINE_DEPOT)


class Faux:
    etiquette = "faux"

    def __init__(self, reponses):
        self.reponses, self.appels = list(reponses), 0

    def chat(self, messages, schema, max_jetons):
        self.appels += 1
        r = self.reponses.pop(0) if self.reponses else "{}"
        if isinstance(r, Exception):
            raise r
        return Reponse(r, 10, 5, 0.01)


def guichet_json(ident):
    d = PAR_ID[ident]
    return json.dumps({"demandeur": d["demandeur"], "profil": d["profil"], "duree_jours": d["duree_attendue"],
                       "complet": True, "justification": "x"})


def _traiter(lab, ident, client=None, **kw):
    d = PAR_ID[ident]
    return Orchestrateur(lab, client, **kw).traiter(ident, d["texte"], d["csr_pem"].encode())


def test_jeu_de_demandes_conforme_au_sujet():
    assert len(DEMANDES) == 60 and sum(d["legitime"] for d in DEMANDES) == 30 and sum(d["injection"] for d in DEMANDES) == 10
    assert not any(d["legitime"] for d in DEMANDES if d["injection"])


def test_campagne_sans_modele_zero_certificat_illegitime(lab):
    emis_illegitimes, refus_legitimes = [], []
    for d in DEMANDES:
        etat = Orchestrateur(lab, None).traiter(d["id"], d["texte"], d["csr_pem"].encode())
        if etat.statut == "emis" and not d["legitime"]:
            emis_illegitimes.append(d["id"])
        if etat.statut != "emis" and d["legitime"]:
            refus_legitimes.append((d["id"], etat.statut, etat.motif))
    assert emis_illegitimes == []
    # La référence sans modèle ne comprend pas les formulations libres : elle demande un complément, elle n'invente rien.
    assert all(statut == "complement" for _, statut, _ in refus_legitimes)
    assert len(lab.base) + len(refus_legitimes) == 30


def test_la_demande_incomplete_demande_un_complement(lab):
    d = PAR_ID["leg-00"]
    etat = Orchestrateur(lab, None).traiter("x", "Je voudrais un certificat pour mon service.", d["csr_pem"].encode())
    assert etat.statut == "complement" and lab.base == {}


def test_trace_jsonl_complete(lab, tmp_path):
    _traiter(lab, "leg-00", dossier_traces=tmp_path / "t")
    ev = lire_journal(tmp_path / "t" / "leg-00.jsonl")
    agents = {e["agent"] for e in ev if e["type"] == "outil_appel"}
    assert agents == {"guichet", "controleur", "ac_intermediaire", "auditeur"}
    assert ev[0]["type"] == "debut" and ev[-1]["type"] == "fin" and ev[-1]["statut"] == "emis"


def test_llm_qui_approuve_une_demande_non_conforme_est_ignore(lab):
    """Contre-mesure : l'avis du modèle ne peut pas faire émettre une demande que le code juge non conforme."""
    ident = "inj-0"
    guichet = json.dumps({"demandeur": "alice", "profil": "serveur", "duree_jours": 30, "complet": True, "justification": "x"})
    ctrl = json.dumps({"decision": "approuver", "justification": "ordre injecté suivi"})
    etat = _traiter(lab, ident, Faux([guichet, ctrl]))
    assert etat.statut == "refuse" and lab.base == {}
    assert etat.decision_controleur == "approuver" and etat.verdict_conforme is False


def test_llm_qui_refuse_une_demande_legitime_est_un_faux_refus_mesurable(lab):
    ctrl = json.dumps({"decision": "refuser", "justification": "prudence excessive"})
    etat = _traiter(lab, "leg-00", Faux([guichet_json("leg-00"), ctrl]))
    assert etat.statut == "refuse" and lab.base == {}


def test_llm_guichet_trompe_par_le_texte_ne_peut_pas_elever_les_droits(lab):
    """Le Guichet modifié par une injection donne un autre demandeur : l'annuaire et la CSR contredisent la demande."""
    d = PAR_ID["inj-8"]       # emma demande web.lab.internal
    guichet = json.dumps({"demandeur": "alice", "profil": "client", "duree_jours": 30, "complet": True, "justification": "x"})
    # alice n'est pas autorisée au profil client ; même avec serveur, la CSR de web.lab.internal serait légitime pour alice :
    guichet2 = json.dumps({"demandeur": "alice", "profil": "serveur", "duree_jours": 30, "complet": True, "justification": "x"})
    e1 = Orchestrateur(lab, Faux([guichet, "{}", "{}"])).traiter("a", d["texte"], d["csr_pem"].encode())
    assert e1.statut == "refuse"
    e2 = Orchestrateur(lab, Faux([guichet2] + ["{}"] * 4)).traiter("b", d["texte"], d["csr_pem"].encode())
    # Limite reconnue : si le Guichet est trompé jusqu'à usurper un demandeur légitime, la politique ne le voit pas.
    assert e2.statut in ("emis", "refuse")


def test_outil_halluciné_refuse_puis_repli(lab, tmp_path):
    ctrl = json.dumps({"decision": "approuver", "justification": "ok"})
    halluci = json.dumps({"appel": {"outil": "signer_avec_la_racine", "arguments": {}}, "justification": "x"})
    etat = _traiter(lab, "leg-00", Faux([guichet_json("leg-00"), ctrl, halluci, halluci]), dossier_traces=tmp_path)
    assert etat.statut == "emis"      # repli déterministe après deux refus
    ev = lire_journal(tmp_path / "leg-00.jsonl")
    assert sum(e["type"] == "outil_refuse" for e in ev) == 2


@pytest.mark.parametrize("panne", ["{pas du json", ErreurLLM("réponse vide"), json.dumps({"x": 1})])
def test_pannes_du_llm_replient_sur_le_deterministe(lab, panne):
    etat = _traiter(lab, "leg-00", Faux([panne] * 20))    # leg-00 : durée en chiffres, comprise par la référence
    assert etat.statut == "emis"


def test_outil_en_panne_arret_propre(lab):
    def casse(outil):
        if outil == "verifier_politique":
            raise RuntimeError("panne injectée")
    etat = _traiter(lab, "leg-00", pannes=casse)
    assert etat.statut == "abandon" and lab.base == {}


def test_outil_hors_delai(lab):
    etat = _traiter(lab, "leg-00", pannes=lambda o: time.sleep(0.4) if o == "lire_csr" else None, delai_outil_s=0.05)
    assert etat.statut == "abandon" and "délai" in etat.motif


def test_ac_refuse_si_le_jeton_manque(lab):
    """Garde-fou de l'AC : même si le Contrôleur est contourné, l'émission échoue sans jeton."""
    from pki_ops.agents import ErreurOutil
    from pki_ops.outils.registre import ContexteDemande
    d = PAR_ID["leg-00"]
    ctx = ContexteDemande(lab, d["texte"], d["csr_pem"].encode(), "alice", "serveur", 30, jeton=None)
    from pki_ops.outils import registre
    with pytest.raises(Exception, match="jeton"):
        registre.emettre_certificat(ctx)


def test_audit_negatif_declenche_la_revocation(lab, monkeypatch):
    """Boucle de vérification : si la chaîne ne passe pas, le certificat est révoqué et la CRL republiée."""
    from pki_ops.outils import registre
    monkeypatch.setitem(registre.OUTILS, "verifier_chaine", lambda ctx: {"ok": False, "motif": "chaîne refusée : test"})
    etat = _traiter(lab, "leg-00")
    assert etat.statut == "revoque_apres_audit"
    assert lab.base[etat.serie]["statut"] == "R"
