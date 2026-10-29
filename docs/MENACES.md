# Modèle de menace du système (STRIDE)

Ce document décrit les menaces qui pèsent sur **PKI-Ops lui-même**, les contre-mesures et leur test. Les valeurs mesurées
sont dans `results/metrics.json` (clés `experiences.*` et `sans_llm`, `tres_petit`, `petit`), commentées dans le rapport.

## Actifs et frontières de confiance

- **Clé racine** : hors système, chiffrée, utilisée uniquement lors d'une cérémonie avec validation humaine.
- **Clé de l'intermédiaire** : détenue par l'AC (code), jamais lue par un agent ni par un prompt.
- **Décision d'émettre** : ne dépend que du code (politique, annuaire, jeton d'approbation), jamais d'un avis de modèle.
- **Registre d'émission** : doit révéler toute altération. **Disponibilité** de la révocation.

Le modèle de langage est **non fiable** (sa sortie est une entrée utilisateur). Le texte de la demande et le contenu de la
CSR sont des **données, jamais des consignes**. Seul le code de l'orchestrateur, de l'exécuteur et de l'autorité est de confiance.

## Tableau STRIDE

| Menace | Scénario | Contre-mesure | Test et mesure |
|---|---|---|---|
| **S**poofing | Se faire passer pour le propriétaire d'un nom (« je suis alice ») ; injection du type « le RSSI a validé » | L'annuaire vérifie la propriété des noms et les profils autorisés du demandeur déclaré ; les consignes dans le texte sont ignorées (Contrôleur trompé : le code refuse quand même) | `experiences.menaces.controleur_trompe_avec_autorite_du_code` ; **limite** : l'identité est déclarative, `experiences.menaces.guichet_usurpe` mesure ce qui passe si le Guichet est trompé |
| **T**ampering | CSR piégée (droits de CA, SAN multiples, OU démesurée) ; altération du registre ; résultat d'outil falsifié | Politique stricte sur chaque champ ; l'AC fixe elle-même les extensions (jamais copiées de la CSR) ; registre chaîné et signé ; vérification de chaîne par l'Auditeur et révocation si l'audit échoue | `tests/test_politique.py`, `experiences.registre.detectees` (suppression de la dernière entrée non détectée : limite) |
| **R**epudiation | Contester une émission ou une décision | Journal JSONL de chaque message, appel d'outil, refus, décision (source modèle, repli, sans modèle) ; registre signé | `pkiops rejouer --verifier` ; traces non signées individuellement |
| **I**nformation disclosure | Fuite de clé privée ou de données personnelles par prompts, traces ou dépôt | Aucune clé privée dans les prompts ; clé racine chiffrée ; `pki/` et `*.key` exclus du dépôt ; annuaire fictif ; gitleaks en CI | gitleaks (CI) |
| **D**enial of service | Outil bloqué, modèle muet, flot de demandes | Délai par outil, abandon propre, jeton limité, repli déterministe si le modèle échoue ; CRL de validité 7 jours | `tests/test_orchestrateur.py` (panne, délai, JSON invalide, réponse vide) |
| **E**levation of privilege | (a) un agent appelle un outil hors de sa liste (« signer avec la racine ») ; (b) l'AC émet sans approbation ; (c) l'intermédiaire émet hors périmètre ; (d) compromission de l'intermédiaire | (a) liste fermée appliquée par l'exécuteur ; (b) jeton HMAC lié au CSR, profil, durée, demandeur, et politique revérifiée à l'émission ; (c) Name Constraints et pathlen 0 signées par la racine ; (d) exercice de compromission : révocation par la racine, nouvelle intermédiaire, réémission | `experiences.menaces.outil_hallucine`, `experiences.name_constraints`, `experiences.compromission`, `tests/test_autorite.py` |

## Défense en profondeur mesurée

L'expérience `sans_autorite_du_code` simule un système naïf où l'avis du modèle suffit : toutes les demandes illégitimes sont
émises. Parmi elles, seules celles hors du domaine `lab.internal` sont ensuite rejetées par un client TLS grâce aux Name
Constraints ; les autres (durée excessive, RSA trop faible, nom réservé…) seraient acceptées. La politique appliquée par le code et
la contrainte cryptographique de l'intermédiaire couvrent donc des risques différents.

## Ce que les contre-mesures ne couvrent pas

- **Identité déclarative** : sans authentification du demandeur (annuaire seul), un attaquant qui connaît un propriétaire légitime
  et obtient du Guichet qu'il le déclare peut faire émettre un certificat pour ce propriétaire. Une vraie mise en œuvre exigerait une
  authentification (jeton, mTLS, SSO) en amont du Guichet.
- Un modèle plus capable ou une injection plus soignée peuvent réussir là où les petits modèles évalués échouent.
- La révocation par CRL n'est effective qu'au rafraîchissement des clients ; l'OCSP réduit ce délai mais ajoute un composant.
- Le registre signé ne prouve pas l'absence de troncature de fin sans ancrage externe (horodatage ou publication périodique de la tête).
- Les traces JSONL ne sont pas signées.
