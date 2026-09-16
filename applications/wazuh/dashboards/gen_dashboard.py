#!/usr/bin/env python3
"""Generate an OpenSearch-Dashboards saved-objects NDJSON for OpenSnitch."""

import json

INDEX = "wazuh-alerts-*"
IDX_REF = "kibanaSavedObjectMeta.searchSourceJSON.index"
PREFIX = "starnix-opensnitch-"


def _src(query):
    """searchSourceJSON scoped to OpenSnitch events (plus an extra clause)."""
    q = "rule.groups:opensnitch" + (f" and {query}" if query else "")
    return json.dumps({
        "query": {"language": "kuery", "query": q},
        "filter": [],
        "indexRefName": IDX_REF,
    })


def _viz(vid, title, vis_state, query=""):
    """Build one visualization saved object."""
    return {
        "id": PREFIX + vid,
        "type": "visualization",
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": _src(query)},
        },
        "references": [
            {"name": IDX_REF, "type": "index-pattern", "id": INDEX}
        ],
    }


def _metric(vid, title, agg_type, field=None, query="", fmt="Events"):
    """A single-number metric (count or cardinality)."""
    agg = {"id": "1", "enabled": True, "type": agg_type, "schema": "metric",
           "params": {"field": field} if field else {}}
    state = {"title": title, "type": "metric",
             "aggs": [agg],
             "params": {"metric": {"labels": {"show": True},
                                   "style": {"fontSize": 40}}}}
    return _viz(vid, title, state, query)


def _pie(vid, title, field, query="", size=15):
    """Donut of the top values of a keyword field."""
    state = {"title": title, "type": "pie", "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {"field": field, "size": size, "order": "desc",
                    "orderBy": "1", "otherBucket": True,
                    "otherBucketLabel": "Other"}},
    ], "params": {"type": "pie", "isDonut": True,
                  "legendPosition": "right", "labels": {"show": False}}}
    return _viz(vid, title, state, query)


def _timeline(vid, title, query=""):
    """Stacked bars over time, split by agent (multi-host ready)."""
    state = {"title": title, "type": "histogram", "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric",
         "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram",
         "schema": "segment",
         "params": {"field": "timestamp", "interval": "auto",
                    "min_doc_count": 1}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {"field": "agent.name", "size": 10, "order": "desc",
                    "orderBy": "1"}},
    ], "params": {"type": "histogram",
                  "seriesParams": [{"data": {"id": "1"}, "type": "histogram",
                                    "mode": "stacked",
                                    "valueAxis": "ValueAxis-1"}],
                  "legendPosition": "right"}}
    return _viz(vid, title, state, query)


def _table(vid, title, fields, query="", size=100):
    """Data table bucketed by several keyword fields, counted."""
    aggs = [{"id": "1", "enabled": True, "type": "count", "schema": "metric",
             "params": {}}]
    for i, field in enumerate(fields, start=2):
        aggs.append({"id": str(i), "enabled": True, "type": "terms",
                     "schema": "bucket",
                     "params": {"field": field, "size": size, "order": "desc",
                                "orderBy": "1"}})
    state = {"title": title, "type": "table", "aggs": aggs,
             "params": {"perPage": 15, "showTotal": True,
                        "totalFunc": "sum"}}
    return _viz(vid, title, state, query)


PANELS = [
    _metric("total", "OpenSnitch -- total events", "count"),
    _metric("denies", "OpenSnitch -- denies", "count",
            query="data.bridge_reason:deny"),
    _metric("agents", "OpenSnitch -- reporting hosts", "cardinality",
            field="agent.name"),
    _timeline("timeline", "OpenSnitch -- events over time by host"),
    _pie("destinations", "OpenSnitch -- top destinations",
         "data.Event.dst_host"),
    _pie("processes", "OpenSnitch -- top processes",
         "data.Event.process_path"),
    _table("denytable", "OpenSnitch -- denied connections",
           ["agent.name", "data.Event.process_path", "data.Event.dst_host",
            "data.Event.dst_port"], query="data.bridge_reason:deny"),
    _table("egress", "OpenSnitch -- egress (process -> destination)",
           ["agent.name", "data.Event.process_path", "data.Event.dst_host"]),
]

# Dashboard grid: 48-column layout. (x, y, w, h) per panel, in PANELS order.
LAYOUT = [
    (0, 0, 12, 8), (12, 0, 12, 8), (24, 0, 12, 8),
    (0, 8, 48, 12),
    (0, 20, 24, 15), (24, 20, 24, 15),
    (0, 35, 48, 15),
    (0, 50, 48, 18),
]

panels_json, refs = [], []
for i, (panel, (x, y, w, h)) in enumerate(zip(PANELS, LAYOUT)):
    name = f"panel_{i}"
    refs.append({"name": name, "type": "visualization", "id": panel["id"]})
    panels_json.append({
        "version": "2.13.0", "type": "visualization",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
        "panelIndex": str(i), "embeddableConfig": {}, "panelRefName": name,
    })

dashboard = {
    "id": PREFIX + "dashboard",
    "type": "dashboard",
    "attributes": {
        "title": "OpenSnitch -- Application Firewall",
        "hits": 0,
        "description": "Per-application egress verdicts from OpenSnitch agents "
                       "(deny + first-seen). Host-agnostic: any agent shipping "
                       "the opensnitch rule group appears here.",
        "panelsJSON": json.dumps(panels_json),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "version": 1,
        "timeRestore": True,
        "timeTo": "now",
        "timeFrom": "now-24h",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"language": "kuery",
                                                      "query": ""},
                                            "filter": []})
        },
    },
    "references": refs,
}

with open("opensnitch-dashboard.ndjson", "w", encoding="utf-8") as out:
    for obj in PANELS + [dashboard]:
        out.write(json.dumps(obj) + "\n")

print("wrote", len(PANELS) + 1, "saved objects")
