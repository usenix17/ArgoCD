FROM archlinux:latest

# System update + build toolchain. git-lfs provides the `git-lfs` makepkg
# download protocol that some recipes (e.g. darling-git) use for their sources;
# `git lfs install --system` registers the smudge/clean filters for all users.
RUN pacman -Syu --noconfirm \
    base-devel \
    devtools \
    git \
    git-lfs \
    gnupg \
    python \
    python-pip \
    python-yaml \
    python-pytest \
    && git lfs install --system \
    && pacman -Sc --noconfirm

# Install aurutils from AUR (bootstrap via makepkg as build user)
RUN useradd -m -G wheel builder \
    && echo '%wheel ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

# Install Trivy for vulnerability scanning
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

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

# Install aurutils
RUN su - builder -c ' \
    git clone https://aur.archlinux.org/aurutils.git /tmp/aurutils \
    && cd /tmp/aurutils \
    && makepkg -si --noconfirm \
    && rm -rf /tmp/aurutils'

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

# aur-build-all runs all three phases (scan / build / sign). The scan phase
# does the Claude PKGBUILD scan, which is why the anthropic SDK is installed
# above; the key is mounted only in the scan container.
COPY aur-build-all /usr/local/bin/aur-build-all
RUN chmod 755 /usr/local/bin/aur-build-all

USER builder
WORKDIR /build
