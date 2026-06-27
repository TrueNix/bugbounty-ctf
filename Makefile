.PHONY: install install-copy sync-skill check lint test fmt

install:        ## Editable install + symlink the Hermes skill (stays in sync)
	./install.sh

install-copy:   ## Editable install + copy the skill (+ drift-protection hook)
	./install.sh --copy

sync-skill:     ## Re-mirror the repo into the installed (copy-mode) Hermes skill
	bash scripts/sync-skill.sh

check: lint test ## Run the full gate (lint + types + tests)

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/
	mypy src/bugbounty_ctf/

fmt:
	ruff format src/ tests/
	ruff check --fix src/ tests/

test:
	pytest -q
