# Audit de reproductibilité

Audit fait le 30 octobre 2026 sur un clone neuf du dépôt public (commit `5540eaf`), dans un dossier vide, sur Windows 11, Python 3.12, uv.

| Contrôle | Résultat |
|---|---|
| `uv sync` depuis `uv.lock` | réussi |
| `pytest -q` | 67 tests réussis |
| gitleaks (15 commits) | aucune fuite de secret détectée |
| Fichiers privés dans le dépôt | aucun (`PROGRESS.md` et `TODO_HUMAIN.md` sont locaux ; `*.key` ignorés) |

## À savoir

- Les évaluations avec modèle (Ollama) n'ont pas été relancées pendant cet audit : leurs résultats viennent de `results/metrics.json`, produit lors des exécutions décrites dans le rapport. Elles dépendent du matériel (processeur seul) et ne sont pas bit à bit reproductibles.
- Les clés et certificats de test sont générés à l'exécution ; aucune clé privée n'est versionnée.
- Intégrité : `SHA256SUMS` liste l'empreinte de chaque fichier suivi par git ; il est signé avec minisign (`SHA256SUMS.minisig`, clé publique `minisign.pub`).

## Erratum sur la version v1.0.0

Les `SHA256SUMS` publiés avec v1.0.0 (et dans l'archive Zenodo de v1.0.0) ont été calculés sur l'arbre de travail Windows, dont 6 fichiers avaient des fins de ligne CRLF alors que le dépôt contient du LF : `sha256sum -c SHA256SUMS` échoue donc sur ces 6 fichiers dans l'archive v1.0.0. Détecté le 30 octobre 2026 en vérifiant l'archive Zenodo. Le tag v1.0.0 n'est pas déplacé. Sur `main`, `SHA256SUMS` est recalculé à partir du contenu commité (`scripts/sommes_depot.py`) et vérifié sur un clone neuf.
