# Deployment Guide

## PyPI

### Prerequisites

- PyPI account with 2FA
- `build` and `twine` installed: `pip install build twine`

### Release steps

```bash
# 1. Bump version in pyproject.toml
#    [project] version = "0.2.0"

# 2. Tag the release
git tag v0.2.0
git push origin v0.2.0

# 3. Build
python -m build

# 4. Verify the dist
twine check dist/*

# 5. Upload to TestPyPI first (optional)
twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ redops

# 6. Upload to PyPI
twine upload dist/*
```

> Trusted Publisher (OIDC) is the recommended alternative to API tokens — configure it in PyPI project settings to avoid storing credentials.

---

## Docker

### Build and push

```bash
# Build
docker build -t dragonday3/redops:latest .
docker build -t dragonday3/redops:0.2.0 .

# Test locally
docker run --rm dragonday3/redops:latest --help

# Push
docker push dragonday3/redops:latest
docker push dragonday3/redops:0.2.0
```

### Multi-arch build (arm64 + amd64)

```bash
docker buildx create --use
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t dragonday3/redops:latest \
  -t dragonday3/redops:0.2.0 \
  --push .
```

---

## GitHub Actions — Automated Release

Add `.github/workflows/release.yml` to automate PyPI + Docker on tag push:

```yaml
name: Release

on:
  push:
    tags:
      - "v*"

jobs:
  pypi:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # OIDC trusted publisher

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Build
        run: |
          pip install build
          python -m build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1

  docker:
    runs-on: ubuntu-latest
    needs: pypi

    steps:
      - uses: actions/checkout@v4

      - name: Log in to Docker Hub
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}

      - name: Set up QEMU
        uses: docker/setup-qemu-action@v3

      - name: Set up Buildx
        uses: docker/setup-buildx-action@v3

      - name: Extract version tag
        id: tag
        run: echo "VERSION=${GITHUB_REF_NAME#v}" >> $GITHUB_OUTPUT

      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          platforms: linux/amd64,linux/arm64
          push: true
          tags: |
            dragonday3/redops:latest
            dragonday3/redops:${{ steps.tag.outputs.VERSION }}
```

**Required secrets:**
- `DOCKERHUB_USERNAME` — Docker Hub username
- `DOCKERHUB_TOKEN` — Docker Hub access token (not your password)

PyPI uses OIDC trusted publisher — no secret needed, configure once in PyPI project settings.

---

## Self-Hosted (Docker Compose)

```bash
docker compose up -d   # API on :8000
```

Default compose config mounts `./data/` for the SQLite database. Override via env:

```yaml
# docker-compose.override.yml
services:
  redops:
    environment:
      - DATABASE_URL=sqlite+aiosqlite:///./data/redops.db
```

---

## Environment Variables

| Variable | Usage |
|----------|-------|
| `DATABASE_URL` | SQLAlchemy async URL (default: `sqlite+aiosqlite:///./redops.db`) |

API tokens (VirusTotal) are passed per-request to the OPSEC endpoint — never stored as env vars.

---

## PDF Generation — System Dependencies

The PDF reporter uses [WeasyPrint](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html), which requires system libraries:

**Linux (Debian/Ubuntu):**
```bash
apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0
```

**macOS:**
```bash
brew install pango gdk-pixbuf
```

**Windows:** Install [GTK3 runtime](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases).

> PDF generation is optional. HTML, DOCX, and JSON reports work without system dependencies.

---

## Versioning

This project follows [Semantic Versioning](https://semver.org/):

- `MAJOR` — breaking CLI, SDK, or API interface changes
- `MINOR` — new OPSEC checks, new report formats, new API endpoints
- `PATCH` — bug fixes, improvements, dependency updates

Current: **v0.1.0** (initial release — 9 OPSEC checks, MITRE ATT&CK integration, 4 report formats, REST API, CLI, SDK)
