# Runbook: fast-storage ZFS -> XFS, one pve node at a time

## Why
pve hosts hard-freeze recurringly from a ZFS `txg_sync` stall on the USB-C
Samsung T7 `fast-storage` pool under Longhorn write load (see
reference_pve_usb_zfs_txg_stall). Longhorn already replicates/snapshots/checksums
at the block layer, so ZFS underneath is redundant and is the thing that freezes.
Fix: back the VM's Longhorn data disk with a **raw file on a plain XFS filesystem**
instead of a ZFS zvol. The in-VM view is unchanged (Talos formats the blank disk
XFS, mounts /var/lib/longhorn) -- Longhorn rebuilds the node's replicas afterward.

## Layering (per node)
host USB-C Samsung T7  ->  ZFS pool `fast-storage`  ->  zvol vm-10X-disk-0 (500G)
   ->  VM scsi1 (sdb)  ->  Talos formats XFS -> /var/lib/longhorn  ->  Longhorn disk
TARGET: host USB-C T7  ->  XFS fs (mounted /mnt/fast-storage)  ->  raw file  ->  VM scsi1 ...

## Host <-> node map (pveN .10N <-> Talos .20N)
| host | ip | talos node | vmid | role |
|---|---|---|---|---|
| pve2 | .102 | hb1-9mk | 102 | control-plane |  <- START (least data, just crashed)
| pve1 | .101 | zv2-ov6 | 201 | worker |  <- holds pulse-data (1 replica!)
| pve3 | .103 | p93-8cq | 103 | control-plane |
| pve5 | .105 | 1yg-rc3 | 1005 | worker |
| pve4 | .104 | dg8-q1t | 104 | control-plane |

## GLOBAL pre-flight (before each node)
1. Audit: every Longhorn volume has >=2 HEALTHY replicas on nodes OTHER than the
   target (so losing the target's replicas can't lose data). Re-run the replica
   audit each time.
   - **pulse-data = 1 replica on zv2**: before doing pve1/zv2, bump to >=2
     (`kubectl -n longhorn-system patch volumes.longhorn.io <pv> --type merge
     -p '{"spec":{"numberOfReplicas":2}}'` and wait healthy) OR accept loss
     (config in git, metrics regenerable, restorable from MinIO).
2. etcd 3/3 healthy (`talosctl -n <cp-ip> service etcd`). Only ONE control-plane
   node down at a time.
3. Cluster otherwise green (no unrelated degraded volumes / failing pods).

## PER-NODE procedure (example pve2 / hb1 / vmid 102 / node talos-hb1-9mk)

### 1. Drain Longhorn off the node
```
kubectl -n longhorn-system patch nodes.longhorn.io talos-hb1-9mk --type merge \
  -p '{"spec":{"allowScheduling":false,"evictionRequested":true}}'
```
Wait until the node hosts 0 replicas AND all volumes are healthy:
```
# replicas on the node -> 0
kubectl -n longhorn-system get replicas.longhorn.io -o json | \
  jq -r '[.items[]|select(.spec.nodeID=="talos-hb1-9mk")]|length'
# all volumes healthy
kubectl -n longhorn-system get volumes.longhorn.io -o json | \
  jq -r '[.items[]|select(.status.robustness!="healthy")]|length'
```
NOTE for the flaky node: eviction rebuilds from HEALTHY replicas on good nodes, not
the dying node -- it should not read hb1. If a rebuild stalls (reads hb1 -> txg
stall), fall back: skip eviction, just stop the VM (step 2); Longhorn then rebuilds
from the surviving good replicas (no target read).

### 2. Stop the Talos VM (node goes down; CP -> etcd 2/3)
```
kubectl cordon talos-hb1-9mk
kubectl drain talos-hb1-9mk --ignore-daemonsets --delete-emptydir-data --force --timeout=120s
ssh root@192.168.7.102 'qm stop 102'   # wait: qm status 102 => stopped
```

### 3. Host: ZFS -> XFS on the USB-C SSD
```
ssh root@192.168.7.102
  cat /etc/pve/storage.cfg            # confirm the 'fast-storage' zfspool entry
  zpool status fast-storage           # confirm the USB device (usb-Samsung_PSSD_T7_...)
  pvesm set fast-storage --disable 1  # stop PVE using it
  zpool export fast-storage || zpool destroy fast-storage
  pvesm remove fast-storage           # remove the zfspool storage entry
  DEV=/dev/disk/by-id/usb-Samsung_PSSD_T7_<serial>-0:0   # CONFIRM per host
  wipefs -a "$DEV"
  mkfs.xfs -f -L fast-storage "$DEV"
  mkdir -p /mnt/fast-storage
  echo "LABEL=fast-storage /mnt/fast-storage xfs defaults,nofail,x-systemd.device-timeout=30 0 2" >> /etc/fstab
  systemctl daemon-reload && mount /mnt/fast-storage && df -h /mnt/fast-storage
  pvesm add dir fast-storage --path /mnt/fast-storage --content images --is_mountpoint 1
```

### 4. Recreate the VM data disk as a raw file on XFS
```
  qm set 102 --scsi1 fast-storage:500,format=raw,discard=on,iothread=1,aio=io_uring,cache=none
  qm config 102 | grep scsi1          # verify
```

### 5. Start the VM -> Talos formats the blank disk XFS -> rejoins
```
  qm start 102
```
```
# wait node Ready + etcd back to 3/3
kubectl get node talos-hb1-9mk ; talosctl -n 192.168.7.204 service etcd
kubectl uncordon talos-hb1-9mk
# re-enable Longhorn scheduling on the fresh disk
kubectl -n longhorn-system patch nodes.longhorn.io talos-hb1-9mk --type merge \
  -p '{"spec":{"allowScheduling":true,"evictionRequested":false}}'
```

### 6. GATE: wait for full health before the next node
```
kubectl -n longhorn-system get volumes.longhorn.io -o json | \
  jq -r '[.items[].status.robustness]|group_by(.)|map("\(.[0])=\(length)")|join(" ")'
# all healthy, replicas rebuilt onto the node's fresh XFS disk, etcd 3/3
```
Then repeat for the next node in order. After all 5: no ZFS -> no txg_sync stall;
also frees the ARC RAM. (Consider softdog watchdog as belt-and-suspenders.)

## Open items to confirm live (per host, at execution)
- Exact USB device `by-id` path (serial differs per host).
- `storage.cfg` entry name/type (assume `fast-storage` zfspool).
- Talos auto-formats the blank 500G disk on boot (it did at original VM create; the
  machineconfig disk/user-volume declaration drives it) -- verify on pve2 first.
- raw-file qemu opts: cache=none (safe) vs writeback (faster; data is Longhorn-
  replicated so writeback acceptable) -- decide on pve2.
