"""Cérémonie de la racine : hors système d'agents, avec validation humaine explicite.

La clé racine est chiffrée par un mot de passe que seul l'opérateur connaît. Elle n'est jamais lue
par l'orchestrateur ni par un agent. Ce module est appelé par scripts/ceremonie_racine.py.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import pki


class ValidationHumaineAbsente(Exception):
    pass


def ceremonie(dossier: Path, mot_de_passe_racine: bytes, confirmation_humaine: bool, dns_permis: list[str],
              jours_inter: int = 1825) -> dict:
    """Crée la racine (si absente), puis signe l'intermédiaire : uniquement si l'humain a validé."""
    if not confirmation_humaine:
        raise ValidationHumaineAbsente("la racine ne signe jamais sans validation humaine explicite")
    (dossier / "racine").mkdir(parents=True, exist_ok=True)
    (dossier / "inter").mkdir(parents=True, exist_ok=True)
    cle_racine = pki.generer_cle_ec()
    racine = pki.creer_racine(cle_racine)
    (dossier / "racine" / "racine.key").write_bytes(pki.pem_cle_chiffree(cle_racine, mot_de_passe_racine))
    (dossier / "racine" / "racine.crt").write_bytes(pki.pem_cert(racine))
    cle_inter = pki.generer_cle_ec()
    inter = pki.creer_intermediaire(cle_racine, racine, cle_inter, dns_permis=dns_permis,
                                    url_crl="http://pki.lab.internal/inter.crl", jours=jours_inter)
    fichier_cle = dossier / "inter" / "inter.key"
    fichier_cle.write_bytes(cle_inter.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))
    fichier_cle.chmod(0o600)
    (dossier / "inter" / "inter.crt").write_bytes(pki.pem_cert(inter))
    cle_reg = Ed25519PrivateKey.generate()
    (dossier / "inter" / "registre.key").write_bytes(cle_reg.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (dossier / "inter" / "registre.pub").write_bytes(cle_reg.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return {"racine": racine, "inter": inter, "date": dt.datetime.now(dt.timezone.utc).isoformat()}


def renouveler_intermediaire(dossier: Path, mot_de_passe_racine: bytes, confirmation_humaine: bool,
                             dns_permis: list[str]) -> dict:
    """Nouvelle intermédiaire signée par la racine existante (exercice de compromission)."""
    if not confirmation_humaine:
        raise ValidationHumaineAbsente("la racine ne signe jamais sans validation humaine explicite")
    cle_racine = pki.charger_cle((dossier / "racine" / "racine.key").read_bytes(), mot_de_passe_racine)
    from cryptography import x509
    racine = x509.load_pem_x509_certificate((dossier / "racine" / "racine.crt").read_bytes())
    cle_inter = pki.generer_cle_ec()
    inter = pki.creer_intermediaire(cle_racine, racine, cle_inter, cn="PKI-Ops Lab Issuing CA 2", dns_permis=dns_permis,
                                    url_crl="http://pki.lab.internal/inter.crl")
    return {"cle": cle_inter, "cert": inter, "cle_racine": cle_racine, "racine": racine}
