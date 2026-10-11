# NFS confidentiality -- two-track plan

## Goal / why
Encrypt sensitive NFS data on the wire (NAS 192.168.1.75, FreeBSD 15). The itch:
NFS from nodes/hosts crosses the shared Proxmox VLAN + the inter-VLAN path in
cleartext.

Key constraint discovered: the Talos cluster clients CANNOT join the existing
defined.net managed mesh. defined.net has no supported vanilla-nebula / BYO-cert /
static-host path, and dnclient can't ride the Talos nebula system-extension (the
extension IS vanilla nebula). So NFS-over-Nebula for the cluster would force a
separate self-managed Nebula CA + lighthouse + manual cert rotation + node reimage
+ a boot-ordering race, i.e. a new SPOF in front of the storage linchpin. Rejected.

Split the problem by client type instead:
- Track A (Talos cluster): move sensitive volumes to Longhorn, which is already
  encrypted east-west by the Cilium WireGuard enabled 2026-10-04 (commit fdcdbee).
  Leave non-sensitive / already-encrypted bulk on plain NFS.
- Track B (non-Talos: macOS / Linux / FreeBSD): join defined.net via dnclient and
  mount the NAS over its Nebula overlay IP. Supported on all three OSes.

## Live NFS surface (from running-pod audit, not stale PVs)
Sensitive -> Longhorn (Track A):
- monitoring/prometheus-db                 50Gi  RWO  (TSDB, IOPS-heavy)
- wazuh/wazuh-indexer-data                 50Gi  RWO  (OpenSearch, preserve history)
- wazuh/wazuh-manager-logs                 50Gi  RWO
- harbor/harbor-registry                   50Gi  RWO  (private images, preserve)
- authentik/authentik-media                 5Gi  RWX  (server+worker -> Longhorn RWX)
- authentik/authentik-templates             1Gi  RWX
- homeassistant/homeassistant-config-pvc    1Gi  RWX  (tokens, preserve)
- wazuh/wazuh-manager-{etc,wodles,integrations,api-configuration,active-response,agentless}  small  (batch)

Leave on plain NFS (not secret OR already client-side encrypted):
- jellyfin media, stash, weather, ghost, apprise, aur-mirror repo
- borgwarehouse /mnt/Backup, cometdb /mnt/Comet (encrypted backups)

Capacity OK: ~621Gi @ 3 replicas vs 1835Gi available (2498Gi max). All Longhorn
vols stay at 3 replicas.

## Track A -- Talos sensitive -> Longhorn
Method (per reference_argocd_stateful_migration + reference_postgres_longhorn_migration):
do it in git on main via a temp worktree (parent app-of-apps reverts live kubectl
edits in seconds). Per app: scale consumer to 0, create Longhorn PVC (PGDATA-subdir
rule n/a here -- these are data dirs), copy data with a temp pod mounting old-NFS +
new-Longhorn (rsync), repoint the app PVC, scale up, verify.

- [x] authentik-media (RWX) + authentik-templates (RWX)  -- DONE 2026-10-04: pods on -lh, ready, data intact; commits 99384b3 (PVCs) + 4b2dc0a (repoint). Old NFS PVCs/PVs kept (Retain) for rollback.
- [x] homeassistant-config  -- DONE 2026-10-04: RWO Longhorn + Recreate, 3048 files copied (corrupt WAL/shm junk dropped), pod Ready on -lh. NFS kept (Retain). commits a246413/c0fc41d/02bfb37. (data was 17GB logical, ZFS-compressed to 1.9GB on NFS -> sized PVC 25Gi)
- [x] harbor-registry (RWO)  -- DONE 2026-10-04: 885 files/4.4G copied (uid 10000 preserved), registry Ready on -lh, 3 repos/202 blob-shards intact. commits 9b0108a/1fcbb8f. Needed 1 retry (Longhorn volume faulted mid-copy, degraded replica on talos-hb1-9mk -- flaky node; recovered via autosalvage). NFS kept (Retain).
- [x] wazuh-indexer-data (RWO)  -- DONE 2026-10-04: 24987 files/14.2G copied (uid 1000), indexer green on -lh, 161 indices/437 shards/0 unassigned, wazuh-alerts history intact. commits 27e45a9/060e7bf. NFS kept (Retain).
- [ ] wazuh-manager-logs + small wazuh-manager config vols (batch)
- [ ] prometheus-db (RWO)  -- DECISION: fresh start (simplest) vs rsync copy

## Track B -- non-Talos clients over defined.net
- [ ] Enumerate which hosts (macOS/Linux/FreeBSD) mount which NAS shares + sensitivity
- [ ] Confirm NAS Nebula overlay IP (dnclient already running); nfsd/mountd reachable on nebula iface
- [ ] NAS /etc/exports: allow the Nebula overlay CIDR for the sensitive shares; pf allow 2049/111/mountd on nebula iface
- [ ] defined.net managed firewall: allow NFS ports client-group -> NAS
- [ ] Join each non-Talos host to defined.net (dnclient macOS/Linux/FreeBSD)
- [ ] Repoint those hosts' mounts to NAS-overlay-IP:/share
- [ ] Verify: tcpdump shows nebula udp, no cleartext :2049 for sensitive shares
- [ ] DECISION: keep LAN mounts for convenience, or restrict sensitive shares to overlay-only

## Cleanup (independent, low-risk)
- [ ] Retire confirmed-stale NFS PVCs/PVs: semaphore-postgres, semaphore-workdir (migrated to Longhorn)
- [ ] Verify aur-mirror lock/state + wazuh var-multigroups are truly orphaned (not CronJob-idle) before deleting

## Rejected
- Self-managed Nebula mesh + Talos nebula extension for the cluster: bespoke CA/
  lighthouse/manual-cert-rotation + reimage + SPOF in front of the linchpin, for
  marginal gain over Longhorn + the WG already enabled.

## Verification (done = )
- Track A: each app healthy, data intact, PV is driver.longhorn.io (not nfs), 3 replicas
- Track B: client mounts via overlay IP; LAN capture shows no cleartext NFS for sensitive shares
