# Builds the same platform `make run` runs on the host - see
# aidevops.main's module docstring - into an image `make platform-build`
# loads straight into the kind cluster.
#
# The image keeps the repo's own src/ -> data/ layout (rather than
# installing aidevops as a wheel into site-packages) because
# aidevops.ports.threat_intel.RealThreatIntel locates data/ by walking up
# from its own file - see DEFAULT_DATA_DIR in that module - and that walk
# only lands on the right directory if the shape on disk here matches the
# shape on the host.
FROM python:3.14-slim

# Trivy needs to be a real binary on PATH: RealImageScanner shells out to
# `trivy image` per aidevops.ports.image_scanner, the same way it does on
# the host. Pinned version lives in .trivy-version, the same file
# scripts/ensure-tools.sh reads, so the two never drift apart.
COPY .trivy-version .trivy-version
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin "$(cat .trivy-version)" \
    && rm .trivy-version

COPY --from=ghcr.io/astral-sh/uv:0.9.7 /uv /usr/local/bin/uv

WORKDIR /app

# Dependencies first, so an edit to src/ alone does not bust this layer.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src ./src
COPY data ./data
RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH"

# Runs as a fixed, unprivileged UID rather than a dynamically-created one:
# 02-deployment.yaml's Pod securityContext sets fsGroup against this same
# UID so the /data emptyDir mount it writes DATABASE_PATH into is
# group-writable regardless of what UID the image happens to pick.
RUN useradd --create-home --uid 10001 aidevops
USER aidevops

EXPOSE 8000

CMD ["uvicorn", "aidevops.main:app", "--app-dir", "src", "--host", "0.0.0.0", "--port", "8000"]
