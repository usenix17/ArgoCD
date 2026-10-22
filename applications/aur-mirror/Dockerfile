FROM archlinux:latest

# System update + build toolchain.
RUN pacman -Syu --noconfirm \
    base-devel \
    git \
    gnupg \
    python \
    python-pip \
    python-yaml \
    && pacman -Sc --noconfirm

# Build user: package builds run as this uid inside aur-sandbox. The sudoers
# rule only serves the aurutils bootstrap below and is removed right after it.
RUN useradd -m -G wheel builder \
    && echo '%wheel ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

# Trivy for artifact scanning, pinned: it is a security gate, so the installer
# and the binary come from a fixed release rather than the main branch.
ARG TRIVY_VERSION=v0.76.0
RUN curl -sfL "https://raw.githubusercontent.com/aquasecurity/trivy/${TRIVY_VERSION}/contrib/install.sh" \
    | sh -s -- -b /usr/local/bin "${TRIVY_VERSION}"

# Install the Anthropic SDK for Claude PKGBUILD scanning in an ISOLATED venv.
# Installing it into the system site-packages (pip --break-system-packages) drags
# in certifi/idna/urllib3/charset-normalizer as files pacman does not own, which
# then collide with python-certifi/python-idna when building any package that
# needs python-requests ("failed to commit transaction (conflicting files)").
# The venv keeps those files out of /usr/lib/pythonX.Y/site-packages; only the
# scan phase runs under /opt/scan-venv/bin/python3 (see builder*.yaml). The build
# phase keeps the system python so python package install-paths resolve to /usr.
RUN python -m venv --system-site-packages /opt/scan-venv \
    && /opt/scan-venv/bin/pip install --no-cache-dir anthropic

# Install aurutils (pac runs `aur depends` from this image). -Syu first: the
# toolchain layer above is often a cached build with a stale sync db, and
# makepkg -si then 404s on rotated packages. Passwordless sudo goes away once
# it is installed: nothing at runtime may escalate from the build user.
RUN su - builder -c ' \
    sudo pacman -Syu --noconfirm \
    && git clone https://aur.archlinux.org/aurutils.git /tmp/aurutils \
    && cd /tmp/aurutils \
    && makepkg -si --noconfirm \
    && rm -rf /tmp/aurutils' \
    && sed -i '/^%wheel ALL=(ALL) NOPASSWD: ALL$/d' /etc/sudoers

# Trust the aur-mirror signing key and register the mirror as a pacman repo so
# `makepkg -s` can install already-published mirror packages as build deps
# (e.g. sherlock depends on the AUR package python-torrequest). The build phase
# mounts the repo db read-only at /repo, so file:///repo needs no network; the
# packages and db are signed by the mirror key (repo-add --sign), verified via
# SigLevel against the key trusted here.
COPY aur-mirror-signing-key.asc /etc/pacman.d/aur-mirror-signing-key.asc
# pacman-key --init creates the local signing key that --lsign-key needs (the
# Arch base image ships without it); --populate re-trusts the Arch keyring.
RUN pacman-key --init \
    && pacman-key --populate archlinux \
    && pacman-key --add /etc/pacman.d/aur-mirror-signing-key.asc \
    && pacman-key --lsign-key 8280184D29B65F3C5002A6603959B28BA0CE2B53 \
    && printf '\n[aur-mirror]\nSigLevel = Required\nServer = file:///repo\n' >> /etc/pacman.conf

# aur-build-all is a thin entrypoint for one phase (scan / build / sign); the
# pipeline itself is the aurmirror package beside it. The scan phase runs it
# under the venv python (anthropic SDK); the API key is mounted only there.
COPY aurmirror /usr/local/lib/aur-mirror/aurmirror
COPY aur-build-all /usr/local/bin/aur-build-all
# aur-sandbox: per-package build sandbox (see the script); /mnt/sbx is its root.
COPY aur-sandbox /usr/local/bin/aur-sandbox
COPY fakeroot-userns /usr/local/lib/aur-sandbox/bin/fakeroot
RUN chmod 755 /usr/local/bin/aur-build-all /usr/local/bin/aur-sandbox \
       /usr/local/lib/aur-sandbox/bin/fakeroot \
    && mkdir -p /mnt/sbx

USER builder
WORKDIR /build
