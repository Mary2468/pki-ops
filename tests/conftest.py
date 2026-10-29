"""Fixtures : PKI jetable, clés générées à chaque session de test, jamais écrites dans le dépôt."""

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from pki_ops.outils import pki, politique

RACINE_DEPOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def pol():
    return politique.charger_politique(RACINE_DEPOT / "config" / "politique.yaml")


@pytest.fixture(scope="session")
def hierarchie():
    cle_r, cle_i = pki.generer_cle_ec(), pki.generer_cle_ec()
    racine = pki.creer_racine(cle_r)
    inter = pki.creer_intermediaire(cle_r, racine, cle_i, dns_permis=["lab.internal"],
                                    url_crl="http://pki.lab.internal/inter.crl")
    return {"cle_racine": cle_r, "racine": racine, "cle_inter": cle_i, "inter": inter}


def construire_csr(cn="svc.lab.internal", sans=("svc.lab.internal",), cle=None, ca=False, key_cert_sign=False,
                   extra_sujet=None, autres_sans=()):
    cle = cle or pki.generer_cle_ec()
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)] if cn else []
    for oid, val in (extra_sujet or []):
        attrs.append(x509.NameAttribute(oid, val))
    b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))
    gens = [x509.DNSName(s) for s in sans] + [x509.RFC822Name(a) for a in autres_sans]
    if gens:
        b = b.add_extension(x509.SubjectAlternativeName(gens), critical=False)
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if key_cert_sign:
        b = b.add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False), critical=True)
    csr = b.sign(cle, hashes.SHA256())
    return cle, csr, csr.public_bytes(serialization.Encoding.PEM)
