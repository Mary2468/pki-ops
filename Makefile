.PHONY: test models environment reproduce-small reproduce metrics audit

UV ?= uv

test:
	$(UV) run pytest -q --cov --cov-fail-under=70

models:
	$(UV) run python scripts/verifier_modeles.py

environment:
	$(UV) run python scripts/capturer_environnement.py

metrics:
	$(UV) run python -m pki_ops.metriques
	$(UV) run python site/generer_site.py

# Version courte : quelques minutes, qwen3:0.6b seulement, sous-échantillon, une répétition. C'est ce que lance la CI.
reproduce-small: export PKIOPS_RESULTATS = results_small
reproduce-small: environment
	$(UV) run python scripts/verifier_modeles.py qwen3:0.6b
	$(UV) run pkiops evaluer baseline
	$(UV) run pkiops evaluer experiences
	$(UV) run pkiops evaluer llm --modele tres_petit --repetitions 1 --taille 3
	$(MAKE) metrics

# Protocole du rapport : environ 25 minutes sur CPU (6 demandes avec qwen3:0.6b, 3 avec qwen3:4b, trois répétitions).
reproduce: environment models
	$(UV) run pkiops evaluer baseline
	$(UV) run pkiops evaluer experiences
	$(UV) run pkiops evaluer llm --modele tres_petit --repetitions 3 --taille 6
	$(UV) run pkiops evaluer llm --modele petit --repetitions 3 --taille 3
	$(MAKE) metrics

audit:
	sha256sum -c SHA256SUMS
