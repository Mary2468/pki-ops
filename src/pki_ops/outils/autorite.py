"""Le laboratoire : AC intermédiaire opérée par le système, base d'émission, révocation, registre signé.

La racine n'est PAS ici : elle est utilisée une seule fois, hors système d'agents (outils/ceremonie.py).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import annuaire as ann
from . import pki
from .politique import Politique, charger_politique, lire_csr, verifier_politique
from .registre_emission import RegistreEmission

URL_CRL = "http://pki.lab.internal/inter.crl"


class EmissionRefusee(Exception):
    """L'AC refuse d'émettre : approbation absente ou politique non respectée."""


class Laboratoire:
    def __init__(self, dossier: Path, politique: Politique, annuaire: dict):
        self.dossier, self.politique, self.annuaire = dossier, politique, annuaire
        self.racine = x509.load_pem_x509_certificate((dossier / "racine" / "racine.crt").read_bytes())
        self.inter = x509.load_pem_x509_certificate((dossier / "inter" / "inter.crt").read_bytes())
        self.cle_inter = serialization.load_pem_private_key((dossier / "inter" / "inter.key").read_bytes(), None)
        cle_registre = serialization.load_pem_private_key((dossier / "inter" / "registre.key").read_bytes(), None)
        self.cle_pub_registre = cle_registre.public_key()
        self.registre = RegistreEmission(dossier / "inter" / "registre.jsonl", cle_registre)
        self._secret = os.urandom(32)            # approbations valables pour cette instance seulement
        self.chemin_base = dossier / "inter" / "base.json"
        self.base: dict[str, dict] = json.loads(self.chemin_base.read_text()) if self.chemin_base.exists() else {}
        self.numero_crl = 1

    # --- approbation et émission -------------------------------------------------------------
    def _jeton(self, csr_pem: bytes, profil: str, duree: int, demandeur: str) -> str:
        msg = hashlib.sha256(csr_pem).hexdigest() + f"|{profil}|{duree}|{demandeur.lower()}"
        return hmac.new(self._secret, msg.encode(), hashlib.sha256).hexdigest()

    def approuver(self, csr_pem: bytes, profil: str, duree: int, demandeur: str) -> dict:
        """Contrôle complet (politique + annuaire). Délivre un jeton uniquement si tout est conforme."""
        info = lire_csr(csr_pem)
        verdict = verifier_politique(info, profil, duree, self.politique)
        identite = ann.interroger(self.annuaire, demandeur, info.sans_dns, profil)
        violations = verdict.violations + identite["problemes"]
        return {"conforme": not violations, "violations": violations,
                "jeton": self._jeton(csr_pem, profil, duree, demandeur) if not violations else None}

    def emettre(self, csr_pem: bytes, profil: str, duree: int, demandeur: str, jeton: str | None,
                quand: dt.datetime | None = None, forcer_sans_controle: bool = False) -> dict:
        """Point d'application de la règle : jeton valide ET politique revérifiée, quoi que dise l'appelant.

        `forcer_sans_controle` n'existe que pour les expériences qui montrent que les Name Constraints
        protègent même quand l'AC « se trompe » ; jamais appelé par un agent.
        """
        if not forcer_sans_controle:
            attendu = self._jeton(csr_pem, profil, duree, demandeur)
            if not jeton or not hmac.compare_digest(jeton, attendu):
                raise EmissionRefusee("jeton d'approbation absent ou invalide")
            verdict = self.approuver(csr_pem, profil, duree, demandeur)
            if not verdict["conforme"]:
                raise EmissionRefusee("; ".join(verdict["violations"]))
        info = lire_csr(csr_pem)
        csr = x509.load_pem_x509_csr(csr_pem)
        cert = pki.emettre_feuille(self.cle_inter, self.inter, csr, self.politique.profils[profil]["usages_cle_etendus"],
                                   duree, info.sans_dns, URL_CRL, debut=quand)
        serie = format(cert.serial_number, "x")
        self.base[serie] = {"sujet": info.cn, "sans": info.sans_dns, "profil": profil, "demandeur": demandeur.lower(),
                            "debut": cert.not_valid_before_utc.isoformat(), "fin": cert.not_valid_after_utc.isoformat(),
                            "statut": "V", "revoque_le": None, "pem": pki.pem_cert(cert).decode()}
        self._sauver()
        self.registre.ajouter({"action": "emission", "serie": serie, "sujet": info.cn, "profil": profil,
                               "demandeur": demandeur.lower(), "fin": cert.not_valid_after_utc.isoformat()})
        return {"serie": serie, "pem": pki.pem_cert(cert).decode(), "certificat": cert}

    # --- révocation, CRL, OCSP, expirations --------------------------------------------------
    def revoquer(self, serie: str, raison: str = "unspecified", quand: dt.datetime | None = None) -> dict:
        if serie not in self.base:
            raise KeyError(f"série inconnue : {serie}")
        if self.base[serie]["statut"] == "R":
            return {"serie": serie, "deja_revoque": True}
        self.base[serie].update(statut="R", revoque_le=(quand or pki.maintenant()).isoformat())
        self._sauver()
        self.registre.ajouter({"action": "revocation", "serie": serie, "raison": raison})
        return {"serie": serie, "deja_revoque": False}

    def crl(self, quand: dt.datetime | None = None) -> x509.CertificateRevocationList:
        revoques = [(int(s, 16), dt.datetime.fromisoformat(b["revoque_le"])) for s, b in self.base.items() if b["statut"] == "R"]
        crl = pki.publier_crl(self.cle_inter, self.inter, revoques, numero=self.numero_crl, maintenant_=quand)
        self.numero_crl += 1
        (self.dossier / "inter" / "inter.crl").write_bytes(crl.public_bytes(serialization.Encoding.PEM))
        return crl

    def index_ocsp(self) -> str:
        """Base au format `openssl ca` (index.txt) pour `openssl ocsp -index`."""
        lignes = []
        for serie, b in sorted(self.base.items()):
            fin = dt.datetime.fromisoformat(b["fin"]).strftime("%y%m%d%H%M%SZ")
            rev = dt.datetime.fromisoformat(b["revoque_le"]).strftime("%y%m%d%H%M%SZ") if b["statut"] == "R" else ""
            lignes.append(f"{b['statut']}\t{fin}\t{rev}\t{serie.upper().zfill(len(serie) + len(serie) % 2)}\tunknown\t/O=PKI-Ops Lab/CN={b['sujet']}")
        return "\n".join(lignes) + "\n"

    def expirations(self, dans_jours: int = 30, quand: dt.datetime | None = None) -> list[dict]:
        t = quand or pki.maintenant()
        sortie = []
        for serie, b in self.base.items():
            if b["statut"] != "V":
                continue
            reste = (dt.datetime.fromisoformat(b["fin"]) - t).total_seconds() / 86400
            if reste <= dans_jours:
                sortie.append({"serie": serie, "sujet": b["sujet"], "jours_restants": round(reste, 2),
                               "niveau": "critique" if reste <= 7 else "alerte", "expire": reste < 0})
        return sorted(sortie, key=lambda x: x["jours_restants"])

    def verifier(self, cert: x509.Certificate, nom_dns: str, profil: str, quand: dt.datetime | None = None) -> tuple[bool, str]:
        client = profil == "client"
        return pki.verifier_chaine(cert, [self.inter], [self.racine], nom_dns, "client" if client else "serveur",
                                   self.crl(quand), quand)

    def _sauver(self) -> None:
        self.chemin_base.write_text(json.dumps(self.base, indent=1, sort_keys=True), encoding="utf-8")


def charger_laboratoire(dossier: Path, depot: Path) -> Laboratoire:
    return Laboratoire(dossier, charger_politique(depot / "config" / "politique.yaml"),
                       ann.charger_annuaire(depot / "config" / "annuaire.yaml"))
