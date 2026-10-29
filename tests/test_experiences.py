"""Expériences de la partie complémentaire : leurs résultats attendus sont des propriétés, pas des valeurs figées."""

import shutil

import pytest

from pki_ops import experiences as ex


def test_renouvellement_respecte_la_fenetre_et_les_noms(tmp_path):
    r = ex.experience_renouvellement(tmp_path)
    assert r["cas_corrects"] == r["cas_total"] == 5
    assert not r["refus_noms_differents"]["ok"] and not r["refus_certificat_revoque"]["ok"]


def test_compromission_invalide_les_anciennes_feuilles_et_en_reemet(tmp_path):
    r = ex.experience_compromission(tmp_path, n_feuilles=6)
    assert r["anciennes_encore_valides"] == 0 and r["nouvelles_valides"] == 6
    assert r["etapes_s"]["total_s"] > 0


def test_name_constraints_refusent_meme_si_l_ac_se_trompe(tmp_path):
    r = ex.experience_name_constraints(tmp_path)
    assert r["hors_domaine_total"] == 4 and r["hors_domaine_refuses_par_le_client"] == 4
    assert r["temoins_dans_le_domaine_acceptes"] == 2


def test_expirations_alertes_justes(tmp_path):
    assert ex.experience_expirations(tmp_path, n=40)["justesse_pct"] == 100.0


def test_registre_detecte_modification_insertion_reordonnancement(tmp_path):
    r = ex.experience_registre(tmp_path, essais=30)
    assert r["registre_intact_valide"]
    for k in ("modification", "insertion", "reordonnancement"):
        assert r["detectees"][k] == 30
    # Limite connue : la troncature de la dernière entrée garde une chaîne valide sans ancrage externe.
    assert r["detectees"]["suppression"] <= 30


def test_mtls_refuse_apres_revocation(tmp_path):
    r = ex.experience_mtls(tmp_path)
    assert r["acceptes_avant"] == 2 and r["refuses_apres"] == 2


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl absent")
def test_ocsp_signale_la_revocation(tmp_path):
    r = ex.experience_ocsp(tmp_path)
    assert r["ocsp"]["statut_avant"] == "good" and r["ocsp"]["autre_certificat_reste"] == "good"
    assert r["ocsp"]["delai_revocation_a_statut_revoque_ms"] is not None
    t = r["crl"]["taille_par_nombre_de_revoques"]
    assert t["1000"]["der_octets"] > t["10"]["der_octets"]


def test_menaces_autorite_du_code_et_limite_d_identite(tmp_path):
    r = ex.experience_menaces(tmp_path)
    assert r["controleur_trompe_avec_autorite_du_code"]["illegitimes_emis"] == 0
    assert r["outil_hallucine"]["illegitimes_emis"] == 0 and r["outil_hallucine"]["appels_refuses"] > 0
    assert r["sans_autorite_du_code"]["illegitimes_emis"] == 30
    assert r["sans_autorite_du_code"]["acceptes_ensuite_par_un_client_tls"] < 30       # les Name Constraints en arrêtent une partie
    # Limite documentée : l'identité du demandeur est déclarative, un Guichet trompé peut faire émettre des demandes illégitimes.
    assert r["guichet_usurpe"]["illegitimes_emis"] > 0
