import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import construire_csr
from pki_ops.outils import pki


def _emettre(h, sans=("svc.lab.internal",), cn="svc.lab.internal", usages=("serverAuth",), jours=30):
    cle, csr, _ = construire_csr(cn=cn, sans=sans)
    cert = pki.emettre_feuille(h["cle_inter"], h["inter"], csr, list(usages), jours, list(sans))
    return cle, cert


def test_racine_auto_signee_et_ca(hierarchie):
    r = hierarchie["racine"]
    assert r.issuer == r.subject
    assert r.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True


def test_intermediaire_a_path_length_zero_et_name_constraints(hierarchie):
    i = hierarchie["inter"]
    bc = i.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca and bc.path_length == 0
    nc = i.extensions.get_extension_for_class(x509.NameConstraints).value
    assert [g.value for g in nc.permitted_subtrees] == ["lab.internal"]
    assert i.issuer == hierarchie["racine"].subject


def test_chaine_valide(hierarchie):
    _, cert = _emettre(hierarchie)
    ok, motif = pki.verifier_chaine(cert, [hierarchie["inter"]], [hierarchie["racine"]], "svc.lab.internal")
    assert ok, motif


def test_chaine_client(hierarchie):
    _, cert = _emettre(hierarchie, usages=("clientAuth",))
    ok, motif = pki.verifier_chaine(cert, [hierarchie["inter"]], [hierarchie["racine"]], "svc.lab.internal",
                                    profil="client")
    assert ok, motif


def test_mauvais_nom_refuse(hierarchie):
    _, cert = _emettre(hierarchie)
    ok, motif = pki.verifier_chaine(cert, [hierarchie["inter"]], [hierarchie["racine"]], "autre.lab.internal")
    assert not ok and "chaîne refusée" in motif


def test_name_constraints_rejettent_un_nom_hors_perimetre(hierarchie):
    """Même si l'émetteur se trompait et signait, le client refuse (exigence complémentaire 3)."""
    _, cert = _emettre(hierarchie, sans=("evil.example.com",), cn="evil.example.com")
    ok, motif = pki.verifier_chaine(cert, [hierarchie["inter"]], [hierarchie["racine"]], "evil.example.com")
    assert not ok


def test_le_refus_vient_bien_des_name_constraints(hierarchie):
    """Témoin : sans Name Constraints sur l'intermédiaire, le même certificat hors périmètre passe."""
    cle_i2 = pki.generer_cle_ec()
    inter2 = pki.creer_intermediaire(hierarchie["cle_racine"], hierarchie["racine"], cle_i2)
    _, csr, _ = construire_csr(cn="evil.example.com", sans=("evil.example.com",))
    cert = pki.emettre_feuille(cle_i2, inter2, csr, ["serverAuth"], 30, ["evil.example.com"])
    ok, motif = pki.verifier_chaine(cert, [inter2], [hierarchie["racine"]], "evil.example.com")
    assert ok, motif


def test_racine_inconnue_refusee(hierarchie):
    autre = pki.creer_racine(pki.generer_cle_ec(), cn="Autre racine")
    _, cert = _emettre(hierarchie)
    ok, _ = pki.verifier_chaine(cert, [hierarchie["inter"]], [autre], "svc.lab.internal")
    assert not ok


def test_certificat_expire(hierarchie):
    _, cert = _emettre(hierarchie, jours=10)
    futur = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=11)
    ok, _ = pki.verifier_chaine(cert, [hierarchie["inter"]], [hierarchie["racine"]], "svc.lab.internal", quand=futur)
    assert not ok


def test_revocation_par_crl(hierarchie):
    _, cert = _emettre(hierarchie)
    crl_vide = pki.publier_crl(hierarchie["cle_inter"], hierarchie["inter"], [])
    assert pki.verifier_chaine(cert, [hierarchie["inter"]], [hierarchie["racine"]], "svc.lab.internal", crl=crl_vide)[0]
    crl = pki.publier_crl(hierarchie["cle_inter"], hierarchie["inter"],
                          [(cert.serial_number, dt.datetime.now(dt.timezone.utc))], numero=2)
    ok, motif = pki.verifier_chaine(cert, [hierarchie["inter"]], [hierarchie["racine"]], "svc.lab.internal", crl=crl)
    assert not ok and motif == "certificat révoqué"
    assert crl.is_signature_valid(hierarchie["inter"].public_key())


def test_emission_refuse_une_csr_a_signature_invalide(hierarchie, monkeypatch):
    _, csr, _ = construire_csr()

    class Faux:
        is_signature_valid = False
    with pytest.raises(ValueError):
        pki.emettre_feuille(hierarchie["cle_inter"], hierarchie["inter"], Faux(), ["serverAuth"], 10, ["a"])


def test_cles_rsa_et_chiffrement_pem(hierarchie):
    cle = pki.generer_cle_rsa(2048)
    pem = pki.pem_cle_chiffree(cle, b"mot-de-passe-de-test")
    assert b"ENCRYPTED" in pem
    assert pki.charger_cle(pem, b"mot-de-passe-de-test").key_size == 2048
    assert pki.pem_cert(hierarchie["racine"]).startswith(b"-----BEGIN CERTIFICATE")
    csr = pki.creer_csr(pki.generer_cle_ec(ec.SECP384R1()), "a.lab.internal", ["a.lab.internal"])
    assert csr.is_signature_valid
