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
	$(UV) run pkiops evaluer llm --modele tres_petit --repetitions 1
	$(MAKE) metrics

# Version complète : plusieurs heures sur CPU (voir docs/rapport.pdf, section Reproductibilité).
reproduce: environment models
	$(UV) run pkiops evaluer baseline
	$(UV) run pkiops evaluer experiences
	$(UV) run pkiops evaluer llm --modele tres_petit --complet
	$(UV) run pkiops evaluer llm --modele petit
	$(MAKE) metrics

audit:
	sha256sum -c SHA256SUMS
