# Carte du système : PKI-Ops

## Objectif et périmètre
Opérer l'autorité **intermédiaire** d'une PKI de laboratoire à deux niveaux : recevoir des demandes de certificats en
langage naturel avec leur CSR, appliquer une politique, émettre, auditer, révoquer, publier CRL et OCSP, renouveler.
Usage prévu : enseignement et étude de l'automatisation encadrée d'une PKI. **Pas un produit de production** : pas
d'authentification forte du demandeur, annuaire fictif, une seule AC, pas de HSM.

## Architecture
Orchestrateur explicite ; cinq agents (Guichet, Contrôleur, AC intermédiaire, Auditeur, Révocation) ; état typé
(Pydantic) ; outils à liste fermée par agent ; boucle de vérification (audit de chaîne négatif : révocation et nouvelle
CRL) ; journal JSONL de tout message et appel d'outil. PKI : racine EC P-256 (cérémonie humaine, clé chiffrée),
intermédiaire EC P-256 avec `pathlen 0` et Name Constraints `lab.internal`, feuilles EC ou RSA ≥ 2048.
Politique : `config/politique.yaml` (domaines, noms réservés, pas de joker, SAN ≤ 5, durée ≤ 90 jours, attributs du sujet bornés).
Prompts versionnés dans `src/pki_ops/prompts/` (historique dans `CHANGELOG.md`).

## Modèles
Ollama 0.40.13, exécution locale sur CPU. Évalués : `qwen3:4b` (sha256:359d7dd4…) et `qwen3:0.6b` (sha256:7df6b6e0…).
Sortie contrainte par schéma JSON, température 0,3, graines 43, 44, 45 pour les répétitions, contexte 8192.
Configuration : `config/experiment.yaml`. Le modèle ne fait aucune opération cryptographique et ne voit jamais le jeton
d'approbation ni la CSR en entier.

## Données
60 demandes synthétiques (`data/demandes.jsonl`) : 30 légitimes, 30 illégitimes dont 10 tentatives d'injection de
consignes. Annuaire de cinq utilisateurs fictifs (prénoms inventés). Aucune donnée personnelle réelle. Les clés
privées des CSR de test sont jetées à la génération : les CSR sont figées dans le dépôt.

## Évaluation
Voir `results/metrics.json` et `docs/rapport.pdf`. Trois configurations : sans modèle, qwen3:0.6b, qwen3:4b.
Mesures dépendant du modèle répétées trois fois. Le modèle de 4 milliards de paramètres est évalué sur un
sous-échantillon de 24 demandes (CPU seul), les autres configurations sur les 60.

## Limites connues
- **Identité déclarative** : un Guichet trompé peut faire émettre une demande qui respecte la politique pour un autre propriétaire (mesuré, `docs/MENACES.md`).
- La référence sans modèle (expressions régulières) ne comprend pas toutes les formulations libres : elle demande alors un complément au lieu d'émettre.
- Le registre signé ne détecte pas la suppression de sa dernière entrée sans ancrage externe.
- Délai OCSP mesuré en local, redémarrage du répondeur `openssl ocsp` inclus (il ne relit pas son index à chaud) ; le délai réel d'une CRL dépend du rafraîchissement des clients.
- Une seule AC intermédiaire, pas de HSM, clés en fichier ; modèles petits.

## Risques et garde-fous
Voir `docs/MENACES.md`. La racine est hors système ; aucune clé privée dans les prompts, traces ou dépôt ; l'émission exige un
jeton que seul le code délivre ; les contraintes de nom sont signées par la racine.

## Maintenance
Projet de cours, non maintenu après l'évaluation. Version publiée : 1.0.0 (DOI Zenodo indiqué dans `CITATION.cff` après publication).
