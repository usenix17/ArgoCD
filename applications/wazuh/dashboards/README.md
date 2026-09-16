# Wazuh dashboards (saved objects)

Source of truth for custom OpenSearch-Dashboards saved objects. These are NOT
Kubernetes manifests -- ArgoCD ignores non-YAML files here (same as `shared/`).
They are imported into the dashboard, not applied to the cluster.

## OpenSnitch -- Application Firewall

`opensnitch-dashboard.ndjson` -- 8 visualizations + 1 dashboard for the
OpenSnitch connection feed (rule group `opensnitch`, rules 100750-100752).
Host-agnostic: it aggregates by `agent.name`, so any agent shipping the
`opensnitch` rule group (Linux via the `opensnitch_wazuh` role, and later
macOS) shows up automatically -- no per-host edits.

Panels: total events, denies, reporting hosts, events-over-time-by-host,
top destinations, top processes, denied-connections table, and a
process -> destination egress table. Index pattern: `wazuh-alerts-*`.

### Regenerate

`gen_dashboard.py` emits the NDJSON deterministically (fixed object IDs, so
re-import upserts rather than duplicating):

```
python3 gen_dashboard.py   # writes opensnitch-dashboard.ndjson
```

### Import

Stack Management -> Saved Objects -> Import (overwrite), or via the API with an
authenticated session:

```
curl -k -u <user> -X POST 'https://wazuh-dash.starnix.net/api/saved_objects/_import?overwrite=true' \
  -H 'osd-xsrf: true' -F file=@opensnitch-dashboard.ndjson
```

Fixed IDs (`starnix-opensnitch-*`) make re-import idempotent.
