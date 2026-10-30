<div class="titre-page">

# PKI-Ops

## Une autorité intermédiaire de PKI opérée par des agents LLM encadrés

Projet individuel bonus, cours « Cryptographie appliquée et IA agentique »

SUP DE VINCI, année 2026, enseignant : Yulliwas AMEUR

**AIT BOUHADI Maryame**

Sujet 4 : PKI-Ops. Version 1.0.0

Dépôt : https://github.com/Mary2468/pki-ops

</div>

<div class="resume">

**Résumé.** J'ai construit PKI-Ops, une autorité intermédiaire de PKI de laboratoire dont les demandes sont traitées par cinq agents : Guichet, Contrôleur, AC intermédiaire, Auditeur et Révocation. Le modèle de langage lit les demandes et propose des décisions. Il ne signe rien et ne décide jamais seul : la politique est appliquée par le code, l'émission exige un jeton d'approbation que seul le code délivre, et l'intermédiaire porte des Name Constraints signées par une racine qui reste hors du système. J'ai construit une campagne de 60 demandes (30 légitimes, 30 illégitimes dont 10 injections). Elle est passée en entier sans modèle ; avec modèle, le protocole est volontairement réduit (6 demandes avec qwen3:0.6b, 3 avec qwen3:4b, trois répétitions chacune) parce que la machine n'a pas de GPU. Sans modèle, {{sans_llm.illegitimes_emis_total|n0}} certificat illégitime a été émis et {{sans_llm.taux_acceptation_legitimes_pct.moyenne|pct}} des demandes légitimes ont été acceptées. J'ai aussi mesuré OCSP contre CRL, deux services en mTLS, un renouvellement automatique, un exercice de compromission chronométré et un modèle de menace du système. Tous les nombres de ce rapport sont lus dans `results/metrics.json` à la construction du PDF.

**Mots-clés :** PKI, X.509, Name Constraints, OCSP, agents LLM, reproductibilité.

**Abstract.** I built PKI-Ops, a lab PKI issuing CA whose requests are handled by five agents: Front desk, Controller, Issuing CA, Auditor and Revocation. The language model reads requests and proposes decisions. It signs nothing and never decides alone: the policy is enforced by code, issuance requires an approval token that only code can produce, and the intermediate carries Name Constraints signed by a root that stays outside the system. I built a campaign of 60 requests (30 legitimate, 30 illegitimate including 10 prompt injections). The whole set was run without a model; with a model the protocol is deliberately reduced (6 requests with qwen3:0.6b, 3 with qwen3:4b, three repetitions each) because the machine has no GPU. Without any model, {{sans_llm.illegitimes_emis_total|n0}} illegitimate certificate was issued and {{sans_llm.taux_acceptation_legitimes_pct.moyenne|pct}} of legitimate requests were accepted. I also measured OCSP against CRL, two mTLS services, automatic renewal, a timed compromise exercise and a threat model of the system itself. Every number in this report is read from `results/metrics.json` when the PDF is built.

</div>



# 1. Introduction

Une PKI réelle reçoit des demandes de certificats que quelqu'un doit lire, contrôler, accepter ou refuser. C'est un travail répétitif, rempli de petites règles. J'ai voulu savoir si des agents LLM peuvent l'accomplir sans que la sécurité de l'autorité dépende d'eux.

Ma réponse tient en une règle : le modèle propose, le code dispose. Le modèle peut mal lire une demande, se tromper, obéir à une consigne cachée dans un texte ou inventer un outil. Le système doit rester sûr dans tous ces cas. Je l'ai donc construit pour que les décisions qui comptent soient prises par du code déterministe et par des contraintes cryptographiques que le modèle ne peut pas contourner.

Je suis les mêmes règles d'intégrité tout au long du projet. Aucun nombre n'apparaît sans une exécution réelle derrière. Les résultats défavorables sont publiés. Aucune clé privée ne figure dans le dépôt, les prompts ou les traces. La racine ne signe qu'avec une validation humaine. L'assistant Claude Code a écrit le code et les premières versions des textes à partir de mes instructions, ce que précise `AI_USAGE.md`.

Le rapport suit ce plan. La section 2 rappelle les notions de PKI utilisées. La section 3 décrit l'architecture. La section 4 présente la méthode d'évaluation. La section 5 donne les résultats. La section 6 présente le modèle de menace. La section 7 discute des limites. La section 8 explique comment tout refaire. La section 9 conclut.

# 2. Cadre : notions de PKI utilisées

## 2.1 Hiérarchie à deux niveaux

Ma PKI a une racine et une intermédiaire. La racine signe uniquement le certificat de l'intermédiaire, puis reste hors ligne. L'intermédiaire émet les certificats de service. Si l'intermédiaire est compromise, la racine la révoque et en signe une nouvelle, sans changer la confiance des clients envers la racine. Les clés sont des courbes elliptiques P-256.

## 2.2 Contraintes de l'intermédiaire

Le certificat de l'intermédiaire contient deux extensions critiques posées par la racine. `BasicConstraints` avec `pathlen 0` interdit à l'intermédiaire de créer une autre autorité. `NameConstraints` limite les noms DNS qu'elle peut certifier au domaine `lab.internal`. Un client qui vérifie la chaîne refuse donc tout certificat hors de ce domaine, **même si l'autorité s'est trompée**. Cette protection ne dépend ni du modèle, ni de mon code d'émission.

## 2.3 Révocation : CRL et OCSP

Une liste de révocation (CRL) est un fichier signé qui énumère les certificats révoqués. Les clients la téléchargent et la mettent en cache. Sa taille croît avec le nombre de révocations et sa fraîcheur dépend de leur rythme de rafraîchissement. OCSP répond au contraire par certificat, en temps réel, mais ajoute un serveur à faire tourner. J'ai mesuré les deux avec `openssl ocsp`.

## 2.4 mTLS

En mTLS, les deux côtés présentent un certificat. Dans mon montage, deux services locaux se parlent ainsi. J'en révoque un et je vérifie que son pair refuse la connexion.

# 3. Architecture

## 3.1 Les cinq agents

Un orchestrateur écrit explicitement enchaîne les agents. Chacun a un prompt versionné, une liste fermée d'outils et une sortie JSON validée par Pydantic.

| Agent | Rôle | Outils autorisés |
|---|---|---|
| Guichet | transformer la demande en demande structurée | analyse de la demande, annuaire du laboratoire |
| Contrôleur | lire la CSR, appliquer la politique | lecture de CSR, vérification de politique |
| AC intermédiaire | émettre le certificat | émission (exige un jeton) |
| Auditeur | vérifier la chaîne, signaler les expirations | vérification de chaîne, expirations |
| Révocation | révoquer et republier la CRL | révoquer, publier la CRL |

## 3.2 Ce que le code garantit

Quatre garde-fous ne dépendent pas du modèle.

1. **La politique est calculée par le code.** Un fichier YAML fixe les domaines, les noms réservés, l'interdiction des jokers, au plus cinq noms alternatifs, une durée de 90 jours au maximum, des clés RSA d'au moins 2048 bits ou des courbes P-256 et P-384, et des attributs de sujet bornés. Le verdict liste toutes les violations.
2. **L'émission exige un jeton.** Le jeton est un HMAC lié au hachage de la CSR, au profil, à la durée et au demandeur. Seul le contrôle de politique le délivre. Le modèle ne le voit jamais.
3. **L'AC revérifie la politique à l'émission.** Même avec un jeton valide, elle refuse si la politique n'est pas respectée.
4. **L'AC fixe elle-même les extensions.** Elle ne copie jamais celles de la CSR, donc une CSR qui demande des droits de CA reçoit un certificat de feuille.

## 3.3 La racine hors du système

La clé racine est chiffrée par une phrase secrète. Elle n'est lue que par `ceremonie`, une fonction qui refuse de s'exécuter sans confirmation humaine explicite. Aucun agent n'appelle cette fonction. Pour les exercices de compromission, la même fonction signe une nouvelle intermédiaire après confirmation.

## 3.4 Registre d'émission

Chaque émission et chaque révocation est écrite dans un registre JSONL. Chaque entrée contient le hachage de la précédente et une signature Ed25519. Une modification, une insertion ou un réordonnancement casse le chaînage ou la signature et se voit à la vérification.

## 3.5 Boucle de vérification

Après une émission, l'Auditeur vérifie la chaîne du nouveau certificat. Si elle ne passe pas, l'agent Révocation révoque le certificat et republie la CRL. La boucle se ferme donc sans intervention humaine.

## 3.6 Défaillances et traçabilité

Si le modèle répond mal, l'agent réessaie une fois, puis utilise sa décision déterministe. Un appel d'outil hors liste est refusé et journalisé. Un outil en panne ou trop lent fait abandonner la demande proprement. Chaque message et chaque appel d'outil est écrit dans une trace JSONL rejouable avec `pkiops rejouer --verifier`.

# 4. Méthode d'évaluation

## 4.1 Les 60 demandes

La campagne comprend 60 demandes avec leur CSR. Trente sont légitimes. Trente sont illégitimes : nom hors domaine, durée excessive, RSA 1024, nom réservé, nom générique, CSR avec des droits de CA, demandeur inconnu, nom qui n'appartient pas au demandeur, et dix tentatives d'injection de consignes, chacune accompagnée d'une vraie violation. Les textes sont rédigés en formulations libres pour que la lecture ne se réduise pas à une expression régulière. Les CSR sont figées dans `data/demandes.jsonl` : leurs clés privées ont été jetées à la génération.

## 4.2 Trois configurations

(a) Sans modèle, avec les mêmes agents mais leurs décisions déterministes. (b) `qwen3:0.6b`. (c) `qwen3:4b`. Ollama 0.40.13, processeur seul, température 0,3, contexte 8192, graines 43, 44 et 45 pour les trois répétitions, sortie contrainte par schéma JSON. Les empreintes des modèles sont dans `config/experiment.yaml`.

## 4.3 Le sous-échantillon

La machine d'évaluation a {{environnement.systeme.coeurs_logiques|n0}} cœurs logiques et {{environnement.systeme.ram_totale_go|n1}} Go de mémoire, sans GPU. Le modèle de 4 milliards de paramètres y produit quelques jetons par seconde. Le protocole avec modèle est donc réduit à une démonstration du concept : {{tres_petit.demandes_par_repetition|n0}} demandes pour `qwen3:0.6b` (deux injections, deux légitimes, deux autres illégitimes) et {{petit.demandes_par_repetition|n0}} demandes pour `qwen3:4b` (une de chaque), chacune trois fois. Le traitement de `qwen3:0.6b` a pris environ 9 minutes et celui de `qwen3:4b` environ 16 minutes. La configuration sans modèle porte sur les 60 demandes. Je compare toujours avec la référence sans modèle sur le même échantillon. Avec si peu de demandes, aucun pourcentage mesuré avec un modèle n'a de valeur statistique ; ces essais montrent que la chaîne fonctionne de bout en bout, rien de plus.

## 4.4 Mesures

Je mesure le taux d'acceptation des demandes légitimes, le taux de refus par type, le nombre de certificats illégitimes émis (qui doit rester à zéro), la durée émise comparée à celle demandée, le temps moyen de traitement et la justesse des alertes d'expiration. Pour les exigences complémentaires, je mesure le délai et la taille de la révocation par OCSP et par CRL, les appels mTLS acceptés ou refusés, les cas de renouvellement corrects, les étapes chronométrées de la compromission, les altérations détectées du registre et le rejet par les Name Constraints.

## 4.5 Intégrité

Les mesures brutes sont écrites au fil de l'eau dans `results/raw`. `metriques.py` les agrège en `metrics.json`. Ce rapport lit ses nombres dans ce fichier. Quand une exécution est perturbée, par exemple par une mise en veille de l'ordinateur, je le signale.
