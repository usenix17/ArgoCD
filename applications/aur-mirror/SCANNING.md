# Recipe scanning for the AUR mirror

The June 2026 AUR campaign compromised 1600+ packages by pushing malicious
commits to recipes the world was building straight from HEAD. This mirror does
not build a recipe until Claude has scanned its PKGBUILD (and everything else
the maintainer committed) for supply-chain threats, and the built artifact has
passed a Trivy scan. Packages track AUR HEAD and auto-update as long as they
keep passing -- there is no lockfile to hand-maintain and no per-bump review
queue.

## The pieces

| File / object | Role | Written by |
|---|---|---|
| `allowlist.yaml` | what you *want* mirrored (names + `approved`) | you (or `pac mirror`) |
| `verdicts.json` (state PV) | per package: `commit, recipe_sha256, verdict, risk, summary, findings, kind, lane, last_pass_commit` | scan phase |
| `meta.json` (state PV) | AUR metadata: pkgbase, upstream version, description | scan phase |
| `aur-mirror.built-commits.json`, `aur-mirror.build-failures.json` (repo PV) | which commit each package was built from; which commits failed to build | sign phase |
| `live.json`, `packages.json`, `runs.json`, `logs/` (status PV) | data for the status website | every phase / sign phase |
| `aurmirror/` | the pipeline (Python package) | -- |
| `aur-build-all` | entrypoint: runs one phase per container | -- |
| `site/` | status website + nginx config (kustomize-generated ConfigMaps) | -- |

State lives on NFS PVs, **not** git -- so nothing in this pipeline needs a
repo-write credential in the cluster.

## How a package flows (three phases, three containers)

1. **scan** -- resolves pkgbases for every allowlisted name (batched AUR RPC;
   split children such as `freeipa-client` come from the `freeipa` repo), then
   each package's recipe HEAD. A new or changed commit is reviewed:
   - A pure version/checksum bump against the **last commit that passed** goes
     to the quick Haiku lane; anything else (new package, code change, a diff
     that can't be computed) goes to the escalated multi-pass lane.
   - A recipe the reviewer can't see in full (a file over 16 KB, a binary, or
     over 128 KB total) always escalates, and the model is told what it missed.
   - The result is `pass`, `fail` (a genuine high/critical finding), or
     `error` (no verdict: API outage, missing key, git failure). `error` is
     retried next run and keeps any prior `pass`; a credit/auth error stops
     API calls for the rest of the run.

   This is the **only** container with `ANTHROPIC_API_KEY`, and it **never runs
   makepkg**.
2. **build** -- checks out exactly the scanned commit, re-verifies the recipe
   hash, then hands the checkout to a per-package sandbox (see below). In the
   sandbox: `makepkg --printsrcinfo`, the recipe's signing keys (shipped
   `keys/pgp/*.asc`, then each `validpgpkeys` from ubuntu / openpgp.org /
   archlinux keyservers in turn), and `makepkg`. Between those, the trusted
   orchestrator installs the build deps as root from the signed repos (Arch
   and this mirror) and removes them again afterwards. It then picks up only
   regular-file artifacts, drops split children that aren't allowlisted, and
   Trivy-scans each artifact. One makepkg per pkgbase builds every split
   child. A commit that already failed to build is not retried for 7 days
   unless it changes. No GPG key, no API key here.
3. **sign** -- re-verifies each staged artifact's SHA256, refuses anything not
   newer than the published version (an overlapping run can never downgrade),
   signs in staging, moves into the repo and `repo-add -R`s (rolled back on
   failure; superseded files are deleted). Then prunes de-allowlisted packages,
   sweeps package files the database no longer references, pushes metrics and
   writes the status files.

## Auto-update, and what "held" means

- Because the scan phase resolves a **moving HEAD** every run, a package
  auto-updates the moment upstream advances *and* the new commit passes the
  scan. No pin to bump, no diff to review.
- **Held = fail-closed.** A scan `fail` or `error`, a Trivy CVE/secret, or a
  build failure holds the package: it keeps serving its **last-good published
  build** and raises the `AURPackageHeld` alert. It is **never** an unreviewed
  build, and it **never fails the job**.

## Status website

<https://aur.starnix.net/> shows the live phase and package, held packages
(with how long and how many runs), recent builds with their logs, every package
with its published and upstream version, and run history -- modelled on
aur.chaotic.cx/status. Logs and run history are kept 30 days. The build
container runs untrusted code and can write to the status volume, so nginx
serves `/status/` only as JSON or plain text (`nosniff`, `sandbox` CSP), the
page renders it with `textContent` under a strict CSP, and the signer rewrites
the summary files at the end of every run.

## Security posture (read before you rely on it)

The Claude scan + Trivy are the *sole* gate. There is no human review of
substantive upstream diffs -- a malicious commit that the scan fails to catch
would auto-publish. This is a deliberate tradeoff for homelab scale. If you
ever want a specific high-risk package frozen, `approved: false` it and vendor
a reviewed copy via a first-party `source:` git URL (see `wazuh-agent`).

### Build isolation

The builder pods run under gVisor (`runtimeClassName: gvisor`), so they have
their own kernel, not the node's. Inside, the build container is root (in
gVisor only) and acts as the trusted orchestrator. Recipe code never runs as
that root: every `makepkg` and `gpg` call goes through `aur-sandbox`, which
gives each package:

- fresh user, mount, pid, ipc and uts namespaces, as uid 1000 with no
  capabilities and no sudo (the image drops passwordless sudo, and gVisor
  ignores setuid anyway);
- a read-only `/usr /etc /opt /var/lib/pacman`, and its own work dir at
  `/work` (checkout, keyring, HOME, TMPDIR) as the only writable place;
- no view of staging, other builds, `/repo`, `/status` or the container's
  root, which is unmounted after `pivot_root`.

When makepkg exits, the kernel kills anything it left running in its pid
namespace. Deps are installed before and removed after each build, so every
build starts from the same base, like a clean chroot.

How it's built, and why not the usual tools under gVisor:

- **bubblewrap fails.** Its binds use `open_tree`, which gVisor lacks, and
  loopback setup in a new netns fails too. aur-sandbox uses classic
  `mount(2)` with `unshare` and `pivot_root` instead.
- **`unshare --kill-child` fails.** It needs `pidfd_open`; the pid namespace
  teardown covers the same need.
- **flock does not cross pods.** gVisor keeps file locks inside each pod's
  sandbox, so `flock` on the NFS lock volume no longer serializes the CronJob
  against the PostSync hook. `aurmirror/lock.py` uses a lock file
  (`/lock/.run.lock`) created with `O_EXCL`, atomic on the NFS server, whose
  mtime is a 30s heartbeat. A lock left by a killed pod is broken after 10
  minutes without one.
- **A sandbox can keep seeing a directory another pod removed.** Files are
  rechecked properly, so the lock is a file, not a directory: an `mkdir` lock
  made every waiting pod sit out the full stale timeout after each release.
- **Cluster prerequisites:**
  - `user.max_user_namespaces > 0` on the nodes (Omni ConfigPatch
    `300-user-namespaces`);
  - Cilium `socketLB.hostNamespaceOnly`, or gVisor pods can't reach
    ClusterIPs.
  - See `infrastructure/gvisor/runtimeclass.yaml`.

Known gaps, deferred on purpose:

- **Shared network.** The sandbox shares the pod's network, since sources
  must download. A build can reach whatever the builder egress policy allows
  (see `networkpolicy.yaml`).

## Builder image digest pin

The build manifests and the `pac` default are pinned to an immutable
`@sha256:` digest (not `:latest`), so push access to Harbor cannot swap the
signer's code. Refresh it whenever you change `aurmirror/` or `aur-build-all`
(the image bakes them in):

```sh
cd applications/aur-mirror
python3 -m pytest tests/ -q && pylint aurmirror aur-build-all tests
docker build -t registry.starnix.net/library/aur-builder:latest .
docker push  registry.starnix.net/library/aur-builder:latest
./pin-image.sh    # resolves HEAD digest, rewrites all image refs
```

## Still on you (outside these repos)

- **Client `SigLevel`.** Ensure `selene`'s `/etc/pacman.conf` has the
  `[aur-mirror]` repo at `SigLevel = Required DatabaseRequired`.
- **NFS dirs on mimir** (uid 1000) before first use:
  `/mnt/Store/aur-mirror/{repo,lock,state,status}`.
