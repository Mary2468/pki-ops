# PROGRESS : PKI-Ops (AIT BOUHADI Maryame)

Dernière mise à jour : 2026-10-29.

## Jalon 1 (fait) : squelette et PKI de base
Outils PKI (racine, intermédiaire avec Name Constraints, feuilles, CRL, vérification de chaîne), politique YAML, lecture de CSR.

## Jalon 2 (fait) : agents, orchestrateur, AC, registre
- Cinq agents (`agents.py`) : Guichet, Contrôleur, AC intermédiaire, Révocation, Auditeur. Prompts versionnés dans `prompts/`. Liste fermée d'outils par agent (`outils/registre.py`) appliquée par l'exécuteur.
- Orchestrateur (`orchestrateur.py`) avec boucle de vérification : un audit de chaîne négatif révoque le certificat et republie la CRL.
- La racine est hors du système d'agents (`outils/ceremonie.py`) : elle ne signe qu'avec une validation humaine explicite, sa clé est chiffrée par mot de passe.
- L'AC n'émet qu'avec un jeton d'approbation (HMAC) que seul le contrôle de politique délivre, et revérifie la politique à l'émission. Le modèle ne voit jamais le jeton ni la CSR.
- Registre d'émission chaîné par hachage et signé Ed25519 (`outils/registre_emission.py`), alterations détectées (modification, suppression, réordonnancement, autre clé).
- Annuaire du laboratoire (identité et propriété des noms), 60 demandes de test (`data/demandes.jsonl` : 30 légitimes, 30 illégitimes dont 10 injections).
- 59 tests, couverture des outils 99 %.

À noter : les CSR du jeu de test sont figées dans le dépôt (les clés privées sont jetées à la génération), la génération n'est donc pas régénérée par `make data`.

Bloquant : aucun.

Prochaine étape : serveur OCSP (openssl ocsp) et comparaison CRL, mTLS entre deux services avec refus après révocation, renouvellement automatique, exercice de compromission, évaluation (campagne, ablation, répétitions), modèle de menace, CLI, CI.
