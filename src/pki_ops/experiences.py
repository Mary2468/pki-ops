"""Expériences de la partie « exigences complémentaires » : mTLS, OCSP/CRL, renouvellement, compromission.

Chaque fonction renvoie un dictionnaire de mesures réelles ; scripts/lancer_experiences.py les écrit dans results/raw/.
"""

from __future__ import annotations

import datetime as dt
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import donnees
from .outils import pki
from .outils.autorite import Laboratoire, charger_laboratoire
from .outils.ceremonie import ceremonie, renouveler_intermediaire

RACINE_DEPOT = Path(__file__).resolve().parents[2]
MDP_RACINE = b"mot-de-passe-de-demonstration-non-secret"   # laboratoire jetable : la clé racine n'a aucune valeur
DNS = ["lab.internal"]


def nouveau_labo(dossier: Path) -> Laboratoire:
    ceremonie(dossier, MDP_RACINE, True, DNS)
    return charger_laboratoire(dossier, RACINE_DEPOT)


def cle_et_csr(nom: str):
    cle = ec.generate_private_key(ec.SECP256R1())
    csr = pki.creer_csr(cle, nom, [nom]).public_bytes(serialization.Encoding.PEM)
    return cle, csr


def emettre_pour(lab: Laboratoire, nom: str, demandeur: str, profil: str, jours: int = 30, debut=None):
    cle, csr = cle_et_csr(nom)
    v = lab.approuver(csr, profil, jours, demandeur)
    assert v["conforme"], v["violations"]
    r = lab.emettre(csr, profil, jours, demandeur, v["jeton"], quand=debut)
    r["cle"] = cle
    return r


def pem_cle(cle) -> bytes:
    return cle.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


# --------------------------------------------------------------------------- mTLS ----------------------------------
class Service:
    """Service TLS local exigeant un certificat client ; répond « pong depuis <nom> »."""

    def __init__(self, nom: str, r: dict, lab: Laboratoire, dossier: Path):
        self.nom, self.r, self.lab, self.dossier = nom, r, lab, dossier
        self.chaine = dossier / f"{nom}.chain.pem"
        self.chaine.write_bytes(r["pem"].encode() + pki.pem_cert(lab.inter))
        self.cle = dossier / f"{nom}.key"
        self.cle.write_bytes(pem_cle(r["cle"]))
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.ctx = self.contexte_serveur()
        self.actif = True
        self.dernier_refus: str | None = None
        threading.Thread(target=self._boucle, daemon=True).start()

    def _bundle(self) -> Path:
        crl = self.lab.crl()
        p = self.dossier / f"{self.nom}.trust.pem"
        p.write_bytes(pki.pem_cert(self.lab.racine) + pki.pem_cert(self.lab.inter) + crl.public_bytes(serialization.Encoding.PEM))
        return p

    def contexte_serveur(self) -> ssl.SSLContext:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        c.minimum_version = ssl.TLSVersion.TLSv1_2
        c.load_cert_chain(self.chaine, self.cle)
        c.load_verify_locations(self._bundle())
        c.verify_mode = ssl.CERT_REQUIRED
        c.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        return c

    def contexte_client(self) -> ssl.SSLContext:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.minimum_version = ssl.TLSVersion.TLSv1_2
        c.load_cert_chain(self.chaine, self.cle)
        c.load_verify_locations(self._bundle())
        c.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        return c

    def recharger(self) -> None:
        """Recharge la CRL (le serveur applique alors la révocation)."""
        self.ctx = self.contexte_serveur()

    def _boucle(self) -> None:
        self.sock.settimeout(0.2)
        while self.actif:
            try:
                brut, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with self.ctx.wrap_socket(brut, server_side=True) as s:
                    s.recv(16)
                    s.sendall(f"pong depuis {self.nom}".encode())
            except (ssl.SSLError, OSError) as e:
                self.dernier_refus = str(e)

    def appeler(self, autre: "Service") -> dict:
        c = self.contexte_client()
        try:
            with socket.create_connection(("127.0.0.1", autre.port), timeout=5) as brut:
                with c.wrap_socket(brut, server_hostname=autre.nom) as s:
                    s.sendall(b"ping")
                    rep = s.recv(64).decode()
                    # TLS 1.3 : le client peut finir sa poignée de main avant que le serveur rejette son certificat.
                    return {"de": self.nom, "vers": autre.nom, "ok": bool(rep), "reponse": rep,
                            **({} if rep else {"erreur": "connexion fermée par le serveur sans réponse"})}
        except (ssl.SSLError, OSError) as e:
            return {"de": self.nom, "vers": autre.nom, "ok": False, "erreur": str(e)[:160]}

    def arreter(self) -> None:
        self.actif = False
        time.sleep(0.3)
        self.sock.close()


def experience_mtls(dossier: Path) -> dict:
    lab = nouveau_labo(dossier / "pki")
    a = emettre_pour(lab, "api.lab.internal", "alice", "serveur_et_client")
    b = emettre_pour(lab, "web.lab.internal", "alice", "serveur_et_client")
    sa, sb = Service("api.lab.internal", a, lab, dossier), Service("web.lab.internal", b, lab, dossier)
    try:
        avant = [sa.appeler(sb), sb.appeler(sa)]
        lab.revoquer(b["serie"], "keyCompromise")
        sa.recharger(); sb.recharger()
        apres = [sa.appeler(sb), sb.appeler(sa)]
        refus_serveur = sa.dernier_refus
    finally:
        sa.arreter(); sb.arreter()
    return {"avant_revocation": avant, "apres_revocation_de_web": apres, "refus_vu_par_api": refus_serveur,
            "acceptes_avant": sum(x["ok"] for x in avant), "refuses_apres": sum(not x["ok"] for x in apres)}


# --------------------------------------------------------------------------- OCSP / CRL ---------------------------
def _openssl() -> str:
    exe = shutil.which("openssl")
    if not exe:
        raise RuntimeError("openssl introuvable")
    return exe


def experience_ocsp(dossier: Path, tailles_crl=(1, 10, 100, 1000)) -> dict:
    lab = nouveau_labo(dossier / "pki")
    f1 = emettre_pour(lab, "api.lab.internal", "alice", "serveur")
    f2 = emettre_pour(lab, "web.lab.internal", "alice", "serveur")
    d = dossier / "ocsp"
    d.mkdir(exist_ok=True)
    (d / "inter.crt").write_bytes(pki.pem_cert(lab.inter)); (d / "inter.key").write_bytes(pem_cle(lab.cle_inter))
    (d / "racine.crt").write_bytes(pki.pem_cert(lab.racine))
    (d / "chaine.pem").write_bytes(pki.pem_cert(lab.inter) + pki.pem_cert(lab.racine))
    (d / "f1.crt").write_bytes(f1["pem"].encode()); (d / "f2.crt").write_bytes(f2["pem"].encode())
    (d / "index.txt").write_text(lab.index_ocsp())
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
    def lancer() -> subprocess.Popen:
        proc = subprocess.Popen([_openssl(), "ocsp", "-index", "index.txt", "-port", str(port), "-rsigner", "inter.crt",
                                 "-rkey", "inter.key", "-CA", "chaine.pem"], cwd=d, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        time.sleep(1.0)
        return proc

    srv = lancer()

    def requete(fichier: str) -> tuple[str, float, int]:
        t0 = time.perf_counter()
        p = subprocess.run([_openssl(), "ocsp", "-issuer", "inter.crt", "-cert", fichier, "-url", f"http://127.0.0.1:{port}",
                            "-CAfile", "chaine.pem", "-respout", "rep.der"], cwd=d, capture_output=True, text=True, timeout=30)
        dt_ms = (time.perf_counter() - t0) * 1000
        premiere = (p.stdout.splitlines() or [""])[0]
        etat = "revoked" if premiere.endswith(": revoked") else "good" if premiere.endswith(": good") else "inconnu"
        return etat, dt_ms, (d / "rep.der").stat().st_size if (d / "rep.der").exists() else 0

    try:
        etat_avant, lat_avant, taille_rep = requete("f1.crt")
        t_rev = time.perf_counter()
        lab.revoquer(f1["serie"], "keyCompromise")
        (d / "index.txt").write_text(lab.index_ocsp())
        # openssl 3.1.1 ne relit pas index.txt en cours d'exécution (constaté) : le superviseur redémarre le répondeur.
        srv.terminate(); srv.wait(timeout=10)
        srv = lancer()
        delai_ocsp_ms = None
        for _ in range(200):
            etat, lat, _ = requete("f1.crt")
            if etat == "revoked":
                delai_ocsp_ms = (time.perf_counter() - t_rev) * 1000
                break
            time.sleep(0.05)
        etat_autre, _, _ = requete("f2.crt")
    finally:
        srv.terminate(); srv.wait(timeout=10)
    # CRL : taille selon le nombre de certificats révoqués (série et date uniquement)
    tailles = {}
    t_crl = time.perf_counter()
    lab.crl()
    delai_crl_ms = (time.perf_counter() - t_crl) * 1000
    maintenant = pki.maintenant()
    for n in tailles_crl:
        crl = pki.publier_crl(lab.cle_inter, lab.inter, [(int.from_bytes(f"{i}".encode().ljust(8, b"x"), "big") + 1, maintenant) for i in range(n)])
        tailles[str(n)] = {"der_octets": len(crl.public_bytes(serialization.Encoding.DER))}
    return {"ocsp": {"statut_avant": etat_avant, "latence_requete_ms_avant": round(lat_avant, 1), "taille_reponse_octets": taille_rep,
                      "delai_revocation_a_statut_revoque_ms": round(delai_ocsp_ms, 1) if delai_ocsp_ms else None,
                      "autre_certificat_reste": etat_autre},
            "crl": {"taille_par_nombre_de_revoques": tailles, "delai_republication_ms": round(delai_crl_ms, 1),
                    "validite_jours": 7},
            "remarque": "Le délai OCSP mesuré est local et inclut le redémarrage du répondeur openssl, qui ne relit pas son index à chaud. Pour la CRL, le délai de propagation "
                        "réel est borné par l'intervalle de rafraîchissement des clients, ici la validité de 7 jours."}


# --------------------------------------------------------------------------- renouvellement ------------------------
def renouveler(lab: Laboratoire, cert_actuel: x509.Certificate, csr_pem: bytes, fenetre_jours: int = 30,
               quand: dt.datetime | None = None) -> dict:
    """Renouvellement inspiré d'ACME : le client prouve la possession du certificat courant (présenté en mTLS par le
    service réseau) et la nouvelle CSR doit couvrir les mêmes noms. La politique est revérifiée intégralement."""
    t = quand or pki.maintenant()
    serie = format(cert_actuel.serial_number, "x")
    entree = lab.base.get(serie)
    if entree is None or entree["statut"] != "V":
        return {"ok": False, "motif": "certificat courant inconnu ou révoqué"}
    ok, motif = lab.verifier(cert_actuel, entree["sans"][0], "serveur" if entree["profil"] != "client" else "client", t)
    if not ok:
        return {"ok": False, "motif": f"certificat courant invalide : {motif}"}
    reste = (cert_actuel.not_valid_after_utc - t).total_seconds() / 86400
    if reste > fenetre_jours:
        return {"ok": False, "motif": f"trop tôt : {reste:.1f} jours restants (fenêtre {fenetre_jours})"}
    from .outils.politique import lire_csr
    if lire_csr(csr_pem).sans_dns != entree["sans"]:
        return {"ok": False, "motif": "les noms de la nouvelle CSR diffèrent du certificat courant"}
    duree = 30
    v = lab.approuver(csr_pem, entree["profil"], duree, entree["demandeur"])
    if not v["conforme"]:
        return {"ok": False, "motif": "; ".join(v["violations"])}
    r = lab.emettre(csr_pem, entree["profil"], duree, entree["demandeur"], v["jeton"], quand=t)
    lab.registre.ajouter({"action": "renouvellement", "ancienne": serie, "nouvelle": r["serie"]})
    return {"ok": True, "ancienne": serie, "nouvelle": r["serie"], "jours_restants_avant": round(reste, 2)}


def experience_renouvellement(dossier: Path) -> dict:
    lab = nouveau_labo(dossier / "pki")
    maintenant = pki.maintenant()
    res = []
    for jours_ecoules, attendu in ((5, False), (70, True), (85, True)):
        debut = maintenant - dt.timedelta(days=jours_ecoules)
        r = emettre_pour(lab, f"r{jours_ecoules}.web.lab.internal", "alice", "serveur", 90, debut)
        _, csr = cle_et_csr(lab.base[r["serie"]]["sans"][0])
        sortie = renouveler(lab, r["certificat"], csr, 30, maintenant)
        res.append({"jours_ecoules": jours_ecoules, "renouvellement_attendu": attendu, "obtenu": sortie["ok"], "motif": sortie.get("motif")})
    # renouvellement refusé : noms différents, certificat révoqué
    r = emettre_pour(lab, "api.lab.internal", "alice", "serveur", 30, maintenant - dt.timedelta(days=25))
    _, csr_autre = cle_et_csr("web.lab.internal")
    refus_noms = renouveler(lab, r["certificat"], csr_autre, 30, maintenant)
    lab.revoquer(r["serie"])
    _, csr_ok = cle_et_csr("api.lab.internal")
    refus_revoque = renouveler(lab, r["certificat"], csr_ok, 30, maintenant)
    justes = sum(x["renouvellement_attendu"] == x["obtenu"] for x in res) + (not refus_noms["ok"]) + (not refus_revoque["ok"])
    return {"cas": res, "refus_noms_differents": refus_noms, "refus_certificat_revoque": refus_revoque,
            "cas_corrects": justes, "cas_total": len(res) + 2}


# --------------------------------------------------------------------------- compromission ------------------------
def experience_compromission(dossier: Path, n_feuilles: int = 12) -> dict:
    """Déroule et chronomètre : révocation de l'intermédiaire, nouvelle intermédiaire, réémission, vérification."""
    lab = nouveau_labo(dossier / "pki")
    noms = [(f"svc{i}.web.lab.internal", "alice") for i in range(n_feuilles // 2)] + \
           [(f"svc{i}.db.lab.internal", "bruno") for i in range(n_feuilles - n_feuilles // 2)]
    anciennes = [emettre_pour(lab, n, u, "serveur", 60) for n, u in noms]
    etapes: dict[str, float] = {}
    t0 = time.perf_counter()

    def chrono(nom: str, debut: float) -> float:
        etapes[nom] = round(time.perf_counter() - debut, 4)
        return time.perf_counter()

    t = time.perf_counter()
    lab.registre.ajouter({"action": "compromission_declaree", "cible": "intermediaire"})
    t = chrono("1_declaration_et_journalisation_s", t)
    cle_racine = pki.charger_cle((dossier / "pki" / "racine" / "racine.key").read_bytes(), MDP_RACINE)   # validation humaine simulée
    crl_racine = pki.publier_crl(cle_racine, lab.racine, [(lab.inter.serial_number, pki.maintenant())], jours_validite=1)
    t = chrono("2_revocation_de_l_intermediaire_par_la_racine_s", t)
    nouv = renouveler_intermediaire(dossier / "pki", MDP_RACINE, True, DNS)
    (dossier / "pki" / "inter" / "inter.crt").write_bytes(pki.pem_cert(nouv["cert"]))
    (dossier / "pki" / "inter" / "inter.key").write_bytes(pem_cle(nouv["cle"]))
    t = chrono("3_nouvelle_intermediaire_signee_par_la_racine_s", t)
    lab2 = charger_laboratoire(dossier / "pki", RACINE_DEPOT)
    t = chrono("4_rechargement_de_l_ac_s", t)
    nouvelles = []
    for (n, u), ancien in zip(noms, anciennes):
        nouvelles.append(emettre_pour(lab2, n, u, "serveur", 60))
    t = chrono("5_reemission_des_feuilles_s", t)
    lab2.crl()
    t = chrono("6_publication_de_la_crl_s", t)
    anciennes_ok = sum(pki.verifier_chaine(a["certificat"], [lab.inter], [lab.racine], n, crl_racine=crl_racine)[0]
                       for (n, _), a in zip(noms, anciennes))
    nouvelles_ok = sum(lab2.verifier(r["certificat"], n, "serveur")[0] for (n, _), r in zip(noms, nouvelles))
    t = chrono("7_verification_s", t)
    etapes["total_s"] = round(time.perf_counter() - t0, 4)
    return {"feuilles": n_feuilles, "etapes_s": etapes, "anciennes_encore_valides": anciennes_ok,
            "nouvelles_valides": nouvelles_ok, "registre_entrees": len(lab2.registre.entrees)}


def experience_registre(dossier: Path, essais: int = 200) -> dict:
    """Taux de détection des altérations du registre signé, sur des altérations aléatoires."""
    import json
    import random
    from .outils.registre_emission import lire_registre, verifier_registre
    lab = nouveau_labo(dossier / "pki")
    for i in range(20):
        emettre_pour(lab, f"svc{i}.web.lab.internal", "alice", "serveur")
    ent = lire_registre(lab.registre.chemin)
    rng = random.Random(42)
    detectees = {"modification": 0, "suppression": 0, "reordonnancement": 0, "insertion": 0}
    for _ in range(essais):
        e = json.loads(json.dumps(ent))
        e[rng.randrange(len(e))]["evenement"]["sujet"] = f"x{rng.randrange(10**6)}.lab.internal"
        detectees["modification"] += not verifier_registre(e, lab.cle_pub_registre)[0]
        e = json.loads(json.dumps(ent)); del e[rng.randrange(len(e))]
        detectees["suppression"] += not verifier_registre(e, lab.cle_pub_registre)[0]
        e = json.loads(json.dumps(ent)); i, j = rng.sample(range(len(e)), 2); e[i], e[j] = e[j], e[i]
        detectees["reordonnancement"] += not verifier_registre(e, lab.cle_pub_registre)[0]
        e = json.loads(json.dumps(ent)); e.insert(rng.randrange(1, len(e)), json.loads(json.dumps(e[0])))
        detectees["insertion"] += not verifier_registre(e, lab.cle_pub_registre)[0]
    return {"essais_par_type": essais, "detectees": detectees, "entrees": len(ent),
            "registre_intact_valide": verifier_registre(ent, lab.cle_pub_registre)[0]}


def experience_expirations(dossier: Path, n: int = 60) -> dict:
    """Justesse des alertes à 30 et 7 jours : temps simulé, vérité terrain calculée indépendamment."""
    import random
    lab = nouveau_labo(dossier / "pki")
    rng = random.Random(42)
    base_t = pki.maintenant()
    r = emettre_pour(lab, "api.lab.internal", "alice", "serveur", 90, base_t)
    fin = r["certificat"].not_valid_after_utc
    ok = 0
    cas = []
    for _ in range(n):
        reste = rng.uniform(-5, 60)
        t = fin - dt.timedelta(days=reste)
        a = lab.expirations(30, quand=t)
        niveau = a[0]["niveau"] if a else None
        attendu = None if reste > 30 else ("critique" if reste <= 7 else "alerte")
        ok += niveau == attendu
        cas.append({"jours_restants": round(reste, 2), "attendu": attendu, "obtenu": niveau})
    return {"cas": n, "justes": ok, "justesse_pct": round(100 * ok / n, 2), "exemples": cas[:5]}


def experience_name_constraints(dossier: Path) -> dict:
    """Émission forcée (l'AC « se trompe » : contrôle de politique contourné) pour les demandes hors domaine.

    Le client doit refuser le certificat à cause des Name Constraints de l'intermédiaire, sans aucune liste noire.
    """
    lab = nouveau_labo(dossier / "pki")
    demandes = donnees.lire(RACINE_DEPOT / "data" / "demandes.jsonl")
    cas = []
    for d in demandes:
        if d["categorie"] != "nom_hors_domaine" and not (d["legitime"] and d["id"] in ("leg-00", "leg-01")):
            continue
        csr = d["csr_pem"].encode()
        profil = d.get("profil") or "serveur"
        r = lab.emettre(csr, profil, d.get("duree_attendue") or 30, d.get("demandeur") or "alice", None, forcer_sans_controle=True)
        nom = lab.base[r["serie"]]["sans"][0]
        ok, motif = pki.verifier_chaine(r["certificat"], [lab.inter], [lab.racine], nom, "client" if profil == "client" else "serveur")
        cas.append({"id": d["id"], "categorie": d["categorie"], "nom": nom, "emis_de_force": True,
                    "accepte_par_le_client": ok, "motif": motif[:140]})
    hors = [c for c in cas if c["categorie"] == "nom_hors_domaine"]
    return {"cas": cas, "hors_domaine_refuses_par_le_client": sum(not c["accepte_par_le_client"] for c in hors),
            "hors_domaine_total": len(hors), "temoins_dans_le_domaine_acceptes": sum(c["accepte_par_le_client"] for c in cas if c["categorie"] != "nom_hors_domaine")}
