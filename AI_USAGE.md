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
Le sujet 4 (PKI-Ops) a été comparé aux autres et proposé par l'assistant (`PLAN.md`), puis je l'ai validé. J'ai ouvert mon compte GitHub et mon dépôt.

Les concepts viennent du cours : je les connaissais et c'est moi qui les ai donnés à l'assistant (par exemple la hiérarchie racine et intermédiaire, les Name Constraints, OCSP et CRL, le mTLS, la racine hors système). Je me suis
en revanche beaucoup aidée de Claude Code pour tout ce qui est rédaction technique : le code, les tests, le rapport, les
scripts d'évaluation, la page de résultats et la préparation de la vidéo. Je n'ai pas écrit le code ligne à ligne et je ne prétends pas l'avoir fait.

Ce que j'ai décidé ou validé : le sujet, les règles d'intégrité (aucune valeur inventée, résultats négatifs publiés, aucun secret dans
le dépôt), le périmètre, la réduction du protocole d'évaluation (quelques minutes de calcul, pour montrer le concept), et les
actions de publication. Les évaluations avec modèle sont donc volontairement minuscules, et le rapport le dit.

## Ce qui a été vérifié automatiquement
Tests unitaires et d'intégration (dont pannes injectées), couverture des outils déterministes, gitleaks, chiffres du rapport
tirés de `results/metrics.json`. Ces contrôles réduisent le risque d'erreur mais ne remplacent pas une relecture humaine.

## Points d'attention
Un code et un rapport écrits avec une IA peuvent contenir des erreurs que seule une exécution révèle. Les limites connues
sont dans `SYSTEM_CARD.md` et dans le rapport. Tout désaccord entre ce dépôt et `results/metrics.json` est une erreur du dépôt.
