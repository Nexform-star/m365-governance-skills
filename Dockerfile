# syntax=docker/dockerfile:1
#
# The m365-governance skill scripts as one command-line image. Build and run with:
#   docker build -t m365-governance-skills .
#   docker run --rm -v "$PWD:/work" m365-governance-skills --help
#
# Standard library only: no pip install. The base image is pinned by digest (python:3.12-slim, multi-arch index).
ARG PYTHON_IMAGE=python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

# Assemble the tree in a throwaway stage: only the dispatcher and the skill scripts, byte-compiled, and smoke-tested.
FROM ${PYTHON_IMAGE} AS build
WORKDIR /app
COPY LICENSE README.md pyproject.toml ./
COPY scripts/cli.py scripts/cli.py
COPY plugins/m365-governance/skills/ /tmp/skills/
RUN set -e; for d in /tmp/skills/*/scripts; do \
      skill=$(basename "$(dirname "$d")"); \
      mkdir -p "plugins/m365-governance/skills/$skill/scripts"; \
      cp "$d"/*.py "plugins/m365-governance/skills/$skill/scripts/"; \
    done \
 && chmod 0755 scripts/cli.py plugins/m365-governance/skills/*/scripts/*.py \
 && python -m compileall -q scripts plugins \
 && python scripts/cli.py --help > /dev/null

FROM ${PYTHON_IMAGE}
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="m365-governance-skills" \
      org.opencontainers.image.description="Microsoft 365 governance skill scripts (Graph permission preflight, Entra posture, Intune baseline, groups sprawl, access review) behind one command" \
      org.opencontainers.image.source="https://github.com/basitalisandhu/m365-governance-skills" \
      org.opencontainers.image.url="https://github.com/basitalisandhu/m365-governance-skills" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /app/ /app/
RUN ln -s /app/scripts/cli.py /usr/local/bin/m365-governance \
 && useradd --uid 1000 --user-group --no-create-home --shell /usr/sbin/nologin app
# Mount the files to read (and the folder for any output) at /work.
WORKDIR /work
USER 1000:1000
ENTRYPOINT ["m365-governance"]
CMD ["--help"]
