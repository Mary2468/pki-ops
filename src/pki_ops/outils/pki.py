"""Primitives de la PKI à deux niveaux : racine, intermédiaire, feuille, CRL, vérification."""

from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

EKU = {
    "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
    "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
}


def maintenant() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def generer_cle_ec(courbe: ec.EllipticCurve | None = None) -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(courbe or ec.SECP256R1())


def generer_cle_rsa(taille: int = 3072) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=taille)


def nom(cn: str, organisation: str = "PKI-Ops Lab") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _hash_pour(cle) -> hashes.HashAlgorithm:
    return hashes.SHA384() if isinstance(cle, ec.EllipticCurvePrivateKey) and cle.curve.key_size == 384 else hashes.SHA256()


def creer_racine(cle_racine, cn: str = "PKI-Ops Lab Root CA", jours: int = 3650,
                 debut: dt.datetime | None = None) -> x509.Certificate:
    debut = debut or maintenant()
    sujet = nom(cn)
    return (
        x509.CertificateBuilder()
        .subject_name(sujet).issuer_name(sujet)
        .public_key(cle_racine.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(debut).not_valid_after(debut + dt.timedelta(days=jours))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(cle_racine.public_key()), critical=False)
        .sign(cle_racine, _hash_pour(cle_racine))
    )


def creer_intermediaire(cle_racine, cert_racine: x509.Certificate, cle_inter,
                        cn: str = "PKI-Ops Lab Issuing CA", jours: int = 1825,
                        dns_permis: list[str] | None = None, url_crl: str | None = None,
                        debut: dt.datetime | None = None) -> x509.Certificate:
    """Cet acte est la « signature manuelle » de la racine : il n'est jamais appelé par un agent."""
    debut = debut or maintenant()
    b = (
        x509.CertificateBuilder()
        .subject_name(nom(cn)).issuer_name(cert_racine.subject)
        .public_key(cle_inter.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(debut).not_valid_after(debut + dt.timedelta(days=jours))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(cle_inter.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(cle_racine.public_key()), critical=False)
    )
    if dns_permis:
        b = b.add_extension(x509.NameConstraints(
            permitted_subtrees=[x509.DNSName(d) for d in dns_permis], excluded_subtrees=None), critical=True)
    if url_crl:
        b = b.add_extension(_points_crl(url_crl), critical=False)
    return b.sign(cle_racine, _hash_pour(cle_racine))


def _points_crl(url: str) -> x509.CRLDistributionPoints:
    return x509.CRLDistributionPoints([x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier(url)], relative_name=None, reasons=None, crl_issuer=None)])


def creer_csr(cle, cn: str, sans: list[str]) -> x509.CertificateSigningRequest:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
        .sign(cle, _hash_pour(cle))
    )


def emettre_feuille(cle_inter, cert_inter: x509.Certificate, csr: x509.CertificateSigningRequest,
                    usages: list[str], jours: int, sans: list[str], url_crl: str | None = None,
                    debut: dt.datetime | None = None) -> x509.Certificate:
    """Émet un certificat feuille. Ne vérifie PAS la politique : c'est le rôle de outils/politique.py."""
    if not csr.is_signature_valid:
        raise ValueError("signature de la CSR invalide")
    debut = debut or maintenant()
    cle_pub = csr.public_key()
    b = (
        x509.CertificateBuilder()
        .subject_name(csr.subject).issuer_name(cert_inter.subject)
        .public_key(cle_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(debut).not_valid_after(debut + dt.timedelta(days=jours))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=isinstance(cle_pub, rsa.RSAPublicKey),
            content_commitment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([EKU[u] for u in usages]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(cle_pub), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(cle_inter.public_key()), critical=False)
    )
    if url_crl:
        b = b.add_extension(_points_crl(url_crl), critical=False)
    return b.sign(cle_inter, _hash_pour(cle_inter))


def publier_crl(cle_inter, cert_inter: x509.Certificate, revoques: list[tuple[int, dt.datetime]],
                jours_validite: int = 7, numero: int = 1, maintenant_: dt.datetime | None = None) -> x509.CertificateRevocationList:
    t = maintenant_ or maintenant()
    b = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(cert_inter.subject)
        .last_update(t).next_update(t + dt.timedelta(days=jours_validite))
        .add_extension(x509.CRLNumber(numero), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(cert_inter.public_key()), critical=False)
    )
    for serie, date in revoques:
        b = b.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serie).revocation_date(date).build())
    return b.sign(cle_inter, _hash_pour(cle_inter))


def est_revoque(crl: x509.CertificateRevocationList, cert: x509.Certificate) -> bool:
    return crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None


def verifier_chaine(feuille: x509.Certificate, intermediaires: list[x509.Certificate],
                    racines: list[x509.Certificate], nom_dns: str, profil: str = "serveur",
                    crl: x509.CertificateRevocationList | None = None,
                    quand: dt.datetime | None = None) -> tuple[bool, str]:
    """Vérifie la chaîne (RFC 5280, contraintes de nom comprises) puis la CRL. Renvoie (ok, motif)."""
    quand = quand or maintenant()
    pb = PolicyBuilder().store(Store(racines)).time(quand)
    try:
        if profil == "client":
            pb.build_client_verifier().verify(feuille, intermediaires)
        else:
            pb.build_server_verifier(x509.DNSName(nom_dns)).verify(feuille, intermediaires)
    except VerificationError as e:
        return False, f"chaîne refusée : {e}"
    if crl is not None and est_revoque(crl, feuille):
        return False, "certificat révoqué"
    return True, "ok"


def pem_cert(c: x509.Certificate) -> bytes:
    return c.public_bytes(serialization.Encoding.PEM)


def pem_cle_chiffree(cle, mot_de_passe: bytes) -> bytes:
    return cle.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.BestAvailableEncryption(mot_de_passe))


def charger_cle(pem: bytes, mot_de_passe: bytes | None):
    return serialization.load_pem_private_key(pem, mot_de_passe)
