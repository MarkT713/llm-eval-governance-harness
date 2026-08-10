.PHONY: install test lint eval serve verify
install:
	python -m pip install -e '.[dev]'
test:
	python -m pytest
lint:
	ruff check .
eval:
	guardbench run --submitter ci-bot
serve:
	uvicorn guardbench.api:app --host 127.0.0.1 --port 8080
verify: lint test
	python -m compileall -q guardbench
	guardbench run --submitter ci-bot
	guardbench verify-audit
