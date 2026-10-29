"""Lecture d'une CSR et vérification de la politique de certification (déterministe)."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID
from pydantic import BaseModel


class InfoCsr(BaseModel):
    cn: str | None
    sans_dns: list[str]
    sans_autres: list[str]
    type_cle: str                 # "rsa", "ec" ou le nom d'un autre type
    taille_cle: int | None
    courbe: str | None
    signature_valide: bool
    demande_ca: bool
    demande_key_cert_sign: bool
    sujet: dict[str, str]         # nom court de l'attribut -> valeur


class Verdict(BaseModel):
    conforme: bool
    violations: list[str]


class Politique(BaseModel):
    version: int
    domaines_autorises: list[str]
    noms_interdits: list[str]
    caracteres_generiques: bool
    san_max: int
    profils: dict[str, dict]
    cles: dict
    sujet: dict


def charger_politique(chemin: Path) -> Politique:
    return Politique(**yaml.safe_load(chemin.read_text(encoding="utf-8")))


def lire_csr(pem: bytes) -> InfoCsr:
    csr = x509.load_pem_x509_csr(pem)
    sujet = {a.rfc4514_attribute_name: str(a.value) for a in csr.subject}
    try:
        san = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns = list(san.get_values_for_type(x509.DNSName))
        autres = [str(g.value) for g in san if not isinstance(g, x509.DNSName)]
    except x509.ExtensionNotFound:
        dns, autres = [], []
    ca = cert_sign = False
    for ext in csr.extensions:
        if isinstance(ext.value, x509.BasicConstraints):
            ca = ext.value.ca
        if isinstance(ext.value, x509.KeyUsage):
            cert_sign = ext.value.key_cert_sign
    cle = csr.public_key()
    if isinstance(cle, rsa.RSAPublicKey):
        type_cle, taille, courbe = "rsa", cle.key_size, None
    elif isinstance(cle, ec.EllipticCurvePublicKey):
        type_cle, taille, courbe = "ec", cle.curve.key_size, cle.curve.name
    else:
        type_cle, taille, courbe = type(cle).__name__, None, None
    return InfoCsr(cn=sujet.get("CN"), sans_dns=dns, sans_autres=autres, type_cle=type_cle,
                   taille_cle=taille, courbe=courbe, signature_valide=csr.is_signature_valid,
                   demande_ca=ca, demande_key_cert_sign=cert_sign, sujet=sujet)


def _dans_domaine(nom: str, domaines: list[str]) -> bool:
    nom = nom.lower()
    return any(nom == d or nom.endswith("." + d) for d in domaines)


def verifier_politique(info: InfoCsr, profil: str, duree_jours: int, politique: Politique) -> Verdict:
    """Liste toutes les violations (pas seulement la première) pour que le refus soit explicable."""
    v: list[str] = []
    if profil not in politique.profils:
        return Verdict(conforme=False, violations=[f"profil inconnu : {profil}"])
    if not info.signature_valide:
        v.append("signature de la CSR invalide (preuve de possession absente)")
    if info.demande_ca or info.demande_key_cert_sign:
        v.append("la CSR demande des droits d'autorité (CA:TRUE ou keyCertSign)")
    if info.sans_autres:
        v.append("types de SAN non autorisés (seuls les noms DNS le sont)")
    if not info.sans_dns:
        v.append("aucun nom DNS dans le SAN")
    if len(info.sans_dns) > politique.san_max:
        v.append(f"trop de SAN ({len(info.sans_dns)} > {politique.san_max})")
    if info.cn and info.cn not in info.sans_dns:
        v.append("le CN doit figurer parmi les SAN")
    interdits = {n.lower() for n in politique.noms_interdits}
    for n in info.sans_dns:
        if "*" in n and not politique.caracteres_generiques:
            v.append(f"nom générique interdit : {n}")
        elif not _dans_domaine(n.replace("*.", ""), politique.domaines_autorises):
            v.append(f"nom hors des domaines autorisés : {n}")
        if n.lower() in interdits:
            v.append(f"nom réservé : {n}")
    if info.type_cle == "rsa":
        if (info.taille_cle or 0) < politique.cles["rsa_taille_min"]:
            v.append(f"clé RSA trop courte : {info.taille_cle} bits")
    elif info.type_cle == "ec":
        if info.courbe not in politique.cles["courbes_ec"]:
            v.append(f"courbe non autorisée : {info.courbe}")
    else:
        v.append(f"type de clé non autorisé : {info.type_cle}")
    maxi = politique.profils[profil]["duree_max_jours"]
    if duree_jours > maxi:
        v.append(f"durée excessive : {duree_jours} jours > {maxi}")
    if duree_jours <= 0:
        v.append("durée non positive")
    motif = re.compile(politique.sujet["motif_valeur"])
    for attr, val in info.sujet.items():
        if attr not in politique.sujet["attributs_autorises"]:
            v.append(f"attribut de sujet non autorisé : {attr}")
        elif len(val) > politique.sujet["longueur_max_valeur"] or not motif.match(val):
            v.append(f"valeur de l'attribut {attr} hors format")
    return Verdict(conforme=not v, violations=v)
