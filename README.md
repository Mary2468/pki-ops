# PKI-Ops

[![CI](https://github.com/Mary2468/pki-ops/actions/workflows/ci.yml/badge.svg)](https://github.com/Mary2468/pki-ops/actions/workflows/ci.yml)
[![Licence code : MIT](https://img.shields.io/badge/code-MIT-blue.svg)](LICENSE)
[![Licence docs et données : CC BY 4.0](https://img.shields.io/badge/docs%20et%20donn%C3%A9es-CC%20BY%204.0-lightgrey.svg)](LICENSE-DOCS.md)

Une autorité intermédiaire de PKI opérée par des agents LLM encadrés par du code déterministe : les agents lisent
les demandes de certificats, contrôlent la politique, émettent, auditent et révoquent, mais **la racine reste hors du
système** et **le code a le dernier mot**. Projet individuel bonus du cours « Cryptographie appliquée et IA agentique »
(SUP DE VINCI, 2026), sujet 4. Autrice : AIT BOUHADI Maryame.

Résultats mesurés : <https://mary2468.github.io/pki-ops/> (page générée depuis `results/metrics.json`).
Rapport : `docs/rapport.pdf`. Audit de reproductibilité : `AUDIT.md`.

## Principe

Cinq agents, orchestrés explicitement, chacun avec un prompt versionné, une liste **fermée** d'outils et une sortie JSON
validée par Pydantic :

| Agent | Rôle | Outils autorisés |
|---|---|---|
| Guichet | transforme une demande en langage naturel en demande structurée | analyse de la demande, annuaire du laboratoire |
| Contrôleur | lit la CSR et applique la politique | lecture de CSR, vérification de politique |
| AC intermédiaire | émet le certificat | émission (exige un jeton d'approbation) |
| Auditeur | vérifie la chaîne, alerte sur les expirations | vérification de chaîne, expirations |
| Révocation | révoque et republie la CRL si l'audit échoue | révoquer, publier la CRL |

Garde-fous qui ne dépendent pas du modèle : la politique (YAML) est évaluée par le code ; l'AC n'émet qu'avec un
jeton HMAC que seul le contrôle de politique délivre et **revérifie la politique à l'émission** ; l'intermédiaire porte
une contrainte de longueur de chemin 0 et des **Name Constraints** (`lab.internal`) signées par la racine ; le registre
d'émission est chaîné par hachage et signé (Ed25519) ; la racine ne signe qu'avec une validation humaine, sa clé est chiffrée.

Exigences complémentaires implémentées : OCSP (`openssl ocsp`) comparé à la CRL, renouvellement automatique de
type ACME sur le réseau local, preuve par les Name Constraints, exercice de compromission de l'intermédiaire
chronométré et rejouable, deux services en mTLS qui refusent un pair révoqué, campagne de 60 demandes.

## Installation et reproduction (5 commandes)

Prérequis : [uv](https://docs.astral.sh/uv/), `openssl` dans le PATH, [Ollama](https://ollama.com) lancé en local et
`ollama pull qwen3:0.6b` (pour la partie avec modèle).

```bash
git clone https://github.com/Mary2468/pki-ops.git && cd pki-ops
uv sync
make test
make reproduce-small
make audit
```

`make reproduce-small` (quelques minutes, qwen3:0.6b) régénère un `results_small/metrics.json`. `make reproduce` refait
l'évaluation du rapport (protocole réduit, environ 25 minutes sur CPU). Sous Windows sans `make` : `scripts/evaluer_tout.ps1`. Configuration
(graine, température, contexte, modèles avec digests) : `config/experiment.yaml` ; machine et versions :
`results/ENVIRONMENT.json`. **Aucune clé réelle n'est utilisée** : chaque exécution crée une PKI jetable dans un dossier temporaire.

## Utilisation

```bash
uv run pkiops traiter leg-00                      # une demande de test, trace des agents affichée
uv run pkiops traiter inj-0 --modele tres_petit   # une tentative d'injection avec un modèle
uv run pkiops rejouer traces/exemple/leg-00.jsonl --verifier
uv run pkiops experience mtls                     # ou ocsp, renouvellement, compromission, registre, name_constraints...
uv run pkiops ceremonie --dossier pki             # cérémonie de la racine : confirmation humaine et phrase secrète
```

## Contenu du dépôt

- `src/pki_ops/outils/` : PKI (`pki.py`), politique, annuaire, autorité, cérémonie, registre signé. `src/pki_ops/` : agents, orchestrateur, expériences, évaluation, métriques, prompts versionnés.
- `config/` : politique, annuaire fictif, paramètres de l'expérience. `data/demandes.jsonl` : les 60 demandes (30 légitimes, 30 illégitimes dont 10 injections) avec leurs CSR figées.
- `results/` : données brutes, `metrics.json`, figures, `ENVIRONMENT.json`. `traces/` : journaux JSONL.
- `docs/` : rapport et modèle de menace (`MENACES.md`). `site/` : générateur de la page de résultats.
- `SYSTEM_CARD.md`, `AI_USAGE.md`, `AUDIT.md`, `CITATION.cff`, `.zenodo.json`, `SHA256SUMS`.

## Limites

Voir `SYSTEM_CARD.md`. L'identité du demandeur est **déclarative** (annuaire sans authentification) : un Guichet trompé
peut faire émettre des demandes illégitimes qui respectent la politique, et cela est mesuré (`docs/MENACES.md`).
Le registre signé ne détecte pas la suppression de sa dernière entrée sans ancrage externe. L'évaluation avec modèle est
volontairement réduite (CPU seul, démonstration du concept) : 6 demandes avec qwen3:0.6b, 3 avec qwen3:4b, trois répétitions.

## Licences

Code : MIT (`LICENSE`). Documentation, données et résultats : CC BY 4.0 (`LICENSE-DOCS.md`).

## Citer

Voir `CITATION.cff`. Le DOI Zenodo est ajouté après la publication de la version 1.0.0.
