.PHONY: test reproduce reproduce-small

test:
	uv run pytest -q --cov --cov-fail-under=70

# Complétées avec l'orchestrateur et la campagne de 60 demandes.
reproduce:
	@echo "non implémenté : jalon évaluation" && exit 1

reproduce-small:
	@echo "non implémenté : jalon évaluation" && exit 1
