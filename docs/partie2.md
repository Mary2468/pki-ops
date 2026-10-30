
# 5. Résultats

Tous les nombres de cette section viennent de `results/metrics.json`. Je commence par dire ce que le protocole permet de conclure. La campagne complète de 60 demandes n'a tourné que sans modèle. Avec modèle, je n'ai pu faire passer que {{tres_petit.demandes_par_repetition|n0}} demandes (`qwen3:0.6b`) et {{petit.demandes_par_repetition|n0}} demandes (`qwen3:4b`), trois fois chacune. Ces essais montrent que la chaîne fonctionne avec un vrai modèle. Ils ne permettent pas de comparer des taux.

## 5.1 Campagne sans modèle (60 demandes)

Le code a émis {{sans_llm.illegitimes_emis_total|n0}} certificat pour une demande illégitime. Les {{experiences.menaces.illegitimes|n0}} demandes illégitimes ont toutes été refusées, y compris les dix injections, dans chaque catégorie ({{sans_llm.taux_refus_par_categorie_pct.injection.moyenne|pct}} de refus pour les injections). La durée émise est correcte dans {{sans_llm.duree_emise_correcte_pct.moyenne|pct}} des cas. Une demande est traitée en {{sans_llm.temps_moyen_par_demande_s.moyenne|n3}} s en moyenne.

Le résultat défavorable est de l'autre côté. Seules {{sans_llm.taux_acceptation_legitimes_pct.moyenne|pct}} des demandes légitimes ont été acceptées. Les {{sans_llm.legitimes_non_emises_par_statut.complement|n0}} autres ont reçu une demande de complément : l'analyse déterministe n'a pas su lire leur formulation libre (une durée écrite en toutes lettres, comme « trois semaines » ou « deux mois »). Ce score n'est pas une faiblesse de sécurité, la demande est simplement mise de côté. C'est en revanche un coût d'usage, et c'est là que le modèle peut servir.

![Taux d'acceptation par configuration](../results/figures/acceptation_par_configuration.png)

## 5.2 Avec modèle : essai de bout en bout

Je donne les valeurs mesurées sans les commenter comme des taux.

| Configuration | Demandes par répétition | Répétitions | Légitimes acceptées | Illégitimes émis | Temps par demande (s) |
|---|---|---|---|---|---|
| Sans modèle | {{sans_llm.demandes_par_repetition|n0}} | {{sans_llm.repetitions|n0}} | {{sans_llm.taux_acceptation_legitimes_pct.moyenne|pct}} | {{sans_llm.illegitimes_emis_total|n0}} | {{sans_llm.temps_moyen_par_demande_s.moyenne|n3}} |
| `qwen3:0.6b` | {{tres_petit.demandes_par_repetition|n0}} | {{tres_petit.repetitions|n0}} | {{tres_petit.taux_acceptation_legitimes_pct.moyenne|pct}} | {{tres_petit.illegitimes_emis_total|n0}} | {{tres_petit.temps_moyen_par_demande_s|ms}} |
| `qwen3:4b` | {{petit.demandes_par_repetition|n0}} | {{petit.repetitions|n0}} | {{petit.taux_acceptation_legitimes_pct.moyenne|pct}} | {{petit.illegitimes_emis_total|n0}} | {{petit.temps_moyen_par_demande_s|ms}} |

Trois observations, toutes limitées à ces échantillons minuscules.

Dans les deux essais avec modèle, aucun certificat illégitime n'a été émis. Le code a refusé tout ce qu'il devait refuser, avec {{tres_petit.appels_llm_par_demande|n2}} (0,6b) et {{petit.appels_llm_par_demande|n2}} (4b) appels au modèle par demande.

Le petit modèle de 0,6 milliard de paramètres a mal lu une demande légitime, `leg-15`, à chaque répétition. La durée demandée était « trois semaines » : il en a tiré une durée nulle, et le code a refusé la demande pour « durée non positive ». Le code a donc rattrapé l'erreur, au prix d'une demande légitime perdue. Le modèle de 4 milliards de paramètres a lu correctement la demande légitime de son échantillon. Je n'ai qu'une demande de ce type pour le 4b, donc je ne conclus rien sur sa fiabilité générale.

Les durées sont très différentes : environ {{petit.temps_moyen_par_demande_s.moyenne|n0}} s par demande pour le 4b contre {{sans_llm.temps_moyen_par_demande_s.moyenne|n3}} s sans modèle, sur un processeur sans GPU. Le coût du modèle est réel et il est visible. Ce que le modèle apporte (lire des formulations libres) doit être comparé à ce coût.

![Taux de refus par catégorie](../results/figures/refus_par_categorie.png)

## 5.3 OCSP contre CRL

Après la révocation d'un certificat, le répondeur OCSP a mis {{experiences.ocsp.ocsp.delai_revocation_a_statut_revoque_ms|n0}} ms à répondre « revoked ». Cette mesure est locale et inclut le redémarrage du répondeur `openssl ocsp`, qui ne relit pas son index à chaud. Une réponse OCSP pèse {{experiences.ocsp.ocsp.taille_reponse_octets|n0}} octets. Un autre certificat est resté « good », comme attendu.

La CRL se republie en {{experiences.ocsp.crl.delai_republication_ms|n1}} ms. Mais son délai réel de propagation dépend du rafraîchissement des clients, borné ici par sa validité de {{experiences.ocsp.crl.validite_jours|n0}} jours. Sa taille augmente avec le nombre de révoqués : {{experiences.ocsp.crl.taille_par_nombre_de_revoques.1.der_octets|n0}} octets pour 1 certificat, {{experiences.ocsp.crl.taille_par_nombre_de_revoques.10.der_octets|n0}} pour 10, {{experiences.ocsp.crl.taille_par_nombre_de_revoques.100.der_octets|n0}} pour 100 et {{experiences.ocsp.crl.taille_par_nombre_de_revoques.1000.der_octets|n0}} pour 1000.

![Taille de la CRL](../results/figures/taille_crl.png)

L'OCSP réagit vite, mais il ajoute un composant en ligne à protéger. La CRL est simple, mais lente à se propager et de plus en plus lourde. Je n'ai pas mesuré le coût côté client.

## 5.4 mTLS entre deux services

Deux services de laboratoire, `web.lab.internal` et `api.lab.internal`, se connectent avec leurs certificats. Avant la révocation, {{experiences.mtls.acceptes_avant|n0}} appels sur 2 réussissent. J'ai révoqué le certificat de `web`. Après cela, {{experiences.mtls.refuses_apres|n0}} appels sur 2 sont refusés. En TLS 1.3, un refus côté serveur apparaît côté client comme une lecture vide, et non comme une alerte nette. Je compte cette lecture vide comme un refus.

![mTLS](img/mtls.png)

## 5.5 Renouvellement automatique

Sur {{experiences.renouvellement.cas_total|n0}} cas de renouvellement, {{experiences.renouvellement.cas_corrects|n0}} sont corrects. Le renouvellement se fait dans une fenêtre de 30 jours avant l'expiration. Deux refus attendus sont aussi vérifiés : un certificat révoqué ne se renouvelle pas, et une CSR dont les noms diffèrent du certificat courant est refusée.

## 5.6 Exercice de compromission de l'intermédiaire

J'ai simulé la compromission de l'intermédiaire avec {{experiences.compromission.feuilles|n0}} certificats feuilles. Les étapes sont déclaration, révocation de l'intermédiaire par la racine, nouvelle intermédiaire, rechargement, réémission des feuilles, publication de la CRL et vérification. Le total est de {{experiences.compromission.etapes_s.total_s|n2}} s, dont {{experiences.compromission.etapes_s.5_reemission_des_feuilles_s|n2}} s pour la réémission. Après l'exercice, {{experiences.compromission.anciennes_encore_valides|n0}} ancien certificat reste valide et {{experiences.compromission.nouvelles_valides|n0}} nouveaux sont valides sur {{experiences.compromission.feuilles|n0}}.

Ce temps est trompeur si on le prend pour une durée réelle. Il mesure le calcul, avec une racine déjà déverrouillée. Dans une vraie organisation, la validation humaine de la racine, la propagation de la nouvelle chaîne et les redémarrages des services dominent. J'ai seulement montré que la procédure est complète et vérifiable.

![Étapes de la compromission](../results/figures/compromission_etapes.png)

## 5.7 Name Constraints, registre, expirations

Les Name Constraints de l'intermédiaire ont fait refuser par un client TLS {{experiences.name_constraints.hors_domaine_refuses_par_le_client|n0}} certificats sur {{experiences.name_constraints.hors_domaine_total|n0}} émis de force hors de `lab.internal`. {{experiences.name_constraints.temoins_dans_le_domaine_acceptes|n0}} certificats témoins dans le domaine ont été acceptés.

Pour le registre, j'ai altéré {{experiences.registre.essais_par_type|n0}} copies par type d'attaque. Les insertions, modifications et réordonnancements sont détectés dans {{experiences.registre.detectees.insertion|n0}}, {{experiences.registre.detectees.modification|n0}} et {{experiences.registre.detectees.reordonnancement|n0}} cas sur {{experiences.registre.essais_par_type|n0}}. Les suppressions ne le sont que dans {{experiences.registre.detectees.suppression|n0}} cas sur {{experiences.registre.essais_par_type|n0}}. C'est une limite réelle : supprimer la dernière entrée d'un registre chaîné ne casse aucun lien. Il faudrait ancrer le dernier condensat hors du registre.

Les alertes d'expiration sont justes dans {{experiences.expirations.justes|n0}} cas sur {{experiences.expirations.cas|n0}}.

# 6. Modèle de menace du système lui-même

Le modèle de langage est une entrée non fiable. Le texte de la demande et le contenu de la CSR sont des données, jamais des consignes. Le tableau STRIDE complet est dans `docs/MENACES.md`. Je présente ici les trois expériences qui évaluent les contre-mesures.

## 6.1 Contre-mesure : l'autorité du code

Je compare deux systèmes sur les {{experiences.menaces.illegitimes|n0}} demandes illégitimes.

| Système | Illégitimes émis | Acceptés ensuite par un client TLS |
|---|---|---|
| Naïf : l'avis du modèle suffit | {{experiences.menaces.sans_autorite_du_code.illegitimes_emis|n0}} sur {{experiences.menaces.illegitimes|n0}} | {{experiences.menaces.sans_autorite_du_code.acceptes_ensuite_par_un_client_tls|n0}} |
| PKI-Ops, contrôleur trompé, le code décide | {{experiences.menaces.controleur_trompe_avec_autorite_du_code.illegitimes_emis|n0}} sur {{experiences.menaces.controleur_trompe_avec_autorite_du_code.essais|n0}} | non applicable |

Dans le système naïf, j'ai simulé un Contrôleur qui approuve toujours, comme s'il avait suivi un ordre injecté. Toutes les demandes illégitimes sont émises. Seules celles qui sortent du domaine `lab.internal` sont ensuite rejetées par un client TLS, grâce aux Name Constraints. Les autres seraient acceptées : durée excessive, RSA 1024, nom réservé. La politique du code et la contrainte cryptographique couvrent donc des risques différents. L'une sans l'autre laisse passer des certificats.

Dans PKI-Ops, le même contrôleur trompé n'obtient rien : le code revérifie la politique à l'émission et le jeton n'est délivré que s'il l'accepte.

## 6.2 Contre-mesure : liste fermée d'outils

J'ai simulé un agent qui appelle un outil inventé, `signer_avec_la_racine`. Sur {{experiences.menaces.outil_hallucine.demandes|n0}} demandes, l'exécuteur a refusé {{experiences.menaces.outil_hallucine.appels_refuses|n0}} appels et la décision déterministe a pris le relais {{experiences.menaces.outil_hallucine.decisions_de_repli|n0}} fois. {{experiences.menaces.outil_hallucine.illegitimes_emis|n0}} certificat illégitime a été émis.

## 6.3 Limite : l'identité est déclarative

Le dernier scénario est défavorable. Le Guichet déclare quel demandeur parle. Si un attaquant le trompe, il peut faire déclarer le propriétaire réel des noms de la CSR. Dans l'expérience, un Guichet trompé ainsi a fait émettre {{experiences.menaces.guichet_usurpe.illegitimes_emis|n0}} certificats sur {{experiences.menaces.guichet_usurpe.essais|n0}} demandes illégitimes. Ces certificats respectent la politique (le Guichet a aussi ramené la durée à 30 jours), mais ils sont émis pour un propriétaire qui ne les a pas demandés.

Je ne corrige pas cette faille, je la mesure. Une vraie mise en œuvre exigerait d'authentifier le demandeur en amont du Guichet, par un jeton, un mTLS ou un SSO. L'annuaire seul ne suffit pas.

# 7. Discussion et limites

## 7.1 Ce que les agents apportent

Le modèle sert à lire des formulations libres. Sans lui, {{sans_llm.legitimes_non_emises_par_statut.complement|n0}} demandes légitimes sur 30 restent en attente. C'est le seul gain que je peux relier à mes mesures, et seulement avec le modèle de 4 milliards de paramètres, sur une demande. Pour la sécurité, le modèle n'apporte rien : tout ce qui protège l'autorité est dans le code et la cryptographie. C'est voulu.

## 7.2 Limites

L'évaluation avec modèle est trop petite pour donner un taux : {{tres_petit.demandes_par_repetition|n0}} et {{petit.demandes_par_repetition|n0}} demandes. Je l'ai réduite parce que la machine n'a pas de GPU et que le modèle de 4 milliards de paramètres produit quelques jetons par seconde. Les trois répétitions mesurent la variabilité du modèle, pas la diversité des demandes. Les écarts-types affichés sont de 0 sur les taux parce que les mêmes demandes donnent les mêmes résultats avec une température faible. Ils ne prouvent pas une stabilité générale.

Autres limites. L'identité du demandeur est déclarative. Le registre ne détecte pas la suppression de sa dernière entrée. Le délai OCSP inclut un redémarrage de répondeur. Il y a une seule autorité intermédiaire, sans HSM, avec des clés en fichiers. Une mise en veille de l'ordinateur pendant une exécution fausse les durées : j'ai relancé les évaluations après avoir réduit le protocole, et je n'utilise aucune durée de l'exécution interrompue.

## 7.3 Ce que je ferais ensuite

Passer à une évaluation plus large sur un serveur avec GPU. Ajouter une authentification du demandeur. Ancrer le registre hors du système. Mesurer le coût côté client de l'OCSP et de la CRL.

# 8. Reproductibilité

L'installation tient en quelques commandes (voir le `README.md`) : cloner le dépôt, `uv sync`, `make test`, puis `make reproduce-small`. `make reproduce-small` rejoue une version courte avec `qwen3:0.6b` seulement, en quelques minutes. C'est ce que lance la CI. `make reproduce` lance l'évaluation de ce rapport. Les modèles sont identifiés par leur empreinte dans `config/experiment.yaml`. L'environnement mesuré est dans `results/ENVIRONMENT.json`. Les traces JSONL sont dans `traces/` et se rejouent avec `pkiops rejouer --verifier`.

![Sortie de la suite de tests](img/tests.png)

Une réexécution ne redonne pas exactement les mêmes durées. Elle redonne les mêmes décisions du code, et des sorties de modèle proches mais pas forcément identiques selon le matériel.

# 9. Conclusion

J'ai construit une autorité intermédiaire dont les agents proposent et dont le code décide. Sur 60 demandes sans modèle, aucun certificat illégitime n'a été émis. Avec deux modèles, sur de très petits échantillons, le résultat est le même. Le gain visible du modèle est la lecture des formulations libres, et son coût est de plusieurs dizaines de secondes par demande sur ma machine. Les garanties de sécurité viennent du code, des Name Constraints et de la racine hors système. La limite que je retiens est l'identité déclarative du demandeur.

# Annexe A. Traces réelles

![Demande légitime](img/traiter_legitime.png)

![Tentative d'injection](img/traiter_injection.png)

![Rejeu d'une trace avec vérification](img/rejouer_verifier.png)

# Annexe B. Intégrité et usage de l'IA

Les nombres du rapport sont lus dans `results/metrics.json`. Le code et les premières versions des textes ont été écrits par l'assistant Claude Code à partir de mes instructions. Ce que j'ai moi-même fait, relu et compris est décrit dans `AI_USAGE.md`. Les clés privées ne figurent ni dans le dépôt, ni dans les prompts, ni dans les traces. Les résultats défavorables sont publiés.
