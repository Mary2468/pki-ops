# PROGRESS : PKI-Ops (AIT BOUHADI Maryame)

Dernière mise à jour : 2026-10-29.

## Jalon 1 (29 au 31 octobre) : squelette et PKI de base

Fait :
- Dépôt public Mary2468/pki-ops, identité Git locale propre.
- Environnement `uv` (Python 3.12), `uv.lock`.
- `outils/pki.py` : racine, intermédiaire (path length 0, Name Constraints `lab.internal`), CSR, feuille, CRL, vérification de chaîne RFC 5280, chiffrement de la clé racine.
- `outils/politique.py` + `config/politique.yaml` : lecture de CSR et vérification de politique (noms, domaines, RSA/EC, durée, droits de CA, SAN, format du sujet). Toutes les violations sont listées.
- 32 tests. Un test témoin montre que le refus d'un nom hors périmètre vient bien des Name Constraints (sans elles, le même certificat passe).

Bloquant : aucun.

Prochaine étape : cérémonie de la racine hors agents (clé chiffrée), puis agents Pydantic, orchestrateur, journal JSONL.
