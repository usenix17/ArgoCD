"""AUR mirror pipeline: Claude-scan, build, Trivy, sign and publish AUR packages.

The pipeline runs as three isolated phases (scan, build, sign) so the
Anthropic API key and the GPG signing key never share a container with
untrusted PKGBUILD code. See SCANNING.md for the trust model.
"""
