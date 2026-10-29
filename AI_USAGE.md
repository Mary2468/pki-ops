# Usage de l'IA dans ce projet

## Dans le produit
Le système utilise des modèles de langage locaux (Ollama : qwen3:0.6b et qwen3:4b) dans cinq rôles d'agents (voir
`SYSTEM_CARD.md`). Les modèles ne signent rien, ne voient pas de clé privée et ne décident pas seuls d'une émission :
le code applique la politique et délivre le jeton d'approbation.

## Dans la fabrication du projet
Le code, les tests, les prompts, la documentation et ce dépôt ont été écrits par **Claude Code** (assistant d'Anthropic,
modèle Claude Sonnet 5.5) à partir du cahier des charges du cours et des instructions de l'équipe, dans une session
de travail dont la trace est conservée. L'assistant a aussi lancé les évaluations, relevé les résultats et rédigé le
rapport à partir de `results/metrics.json`.

## Mon rôle (AIT BOUHADI Maryame)
J'ai choisi le sujet 4, fixé les règles d'intégrité (aucune valeur inventée, résultats négatifs publiés, aucun secret dans le
dépôt, racine hors du système), validé le périmètre, ouvert mon compte GitHub et mon dépôt, et je réalise les actions
manuelles : publication, DOI, signature, dépôt de la fiche.

> **[À COMPLÉTER PAR L'AUTRICE]** Préciser ici ce que j'ai effectivement relu, rejoué et compris (par exemple : j'ai
> refait la cérémonie de la racine à la main, rejoué `pkiops experience compromission`, vérifié les chiffres du
> rapport contre `results/metrics.json`). Cette section ne doit contenir que ce que j'ai réellement fait.

## Ce qui a été vérifié automatiquement
Tests unitaires et d'intégration (dont pannes injectées), couverture des outils déterministes, gitleaks, chiffres du rapport
tirés de `results/metrics.json`. Ces contrôles réduisent le risque d'erreur mais ne remplacent pas une relecture humaine.

## Points d'attention
Un code et un rapport écrits avec une IA peuvent contenir des erreurs que seule une exécution révèle. Les limites connues
sont dans `SYSTEM_CARD.md` et dans le rapport. Tout désaccord entre ce dépôt et `results/metrics.json` est une erreur du dépôt.
