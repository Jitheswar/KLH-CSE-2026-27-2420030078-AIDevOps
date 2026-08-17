.PHONY: run test

# Starts the platform on the host, reading configuration from .env if present.
run:
	uv run $(if $(wildcard .env),--env-file .env,) uvicorn aidevops.main:app --app-dir src --reload

test:
	uv run pytest
