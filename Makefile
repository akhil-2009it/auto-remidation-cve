.PHONY: setup demo clean status

VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

setup:
	python3 -m venv $(VENV)
	$(PIP) install -q -r fix-tool/requirements.txt
	@[ -f fix-tool/.env ] || cp fix-tool/.env.example fix-tool/.env
	@echo ">> edit fix-tool/.env and set ANTHROPIC_API_KEY, then: make demo"

demo:
	@[ -n "$$ANTHROPIC_API_KEY" ] || [ -s fix-tool/.env ] || (echo "set ANTHROPIC_API_KEY in fix-tool/.env"; exit 2)
	cd fix-tool && ../$(PY) tui.py

status:
	@git log --oneline -5
	@git branch -a

clean:
	rm -rf $(VENV) fix-tool/__pycache__
	git checkout -- vulnerable-app/package.json 2>/dev/null || true
	rm -f vulnerable-app/PR_BODY.md
