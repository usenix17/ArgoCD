"""AUR RPC batching and persisted metadata."""
import io
import json
import urllib.error
import urllib.parse

from aurmirror import aur
from aurmirror import config as cfg


def _fake_urlopen(calls, fail=False):
    def opener(url, timeout=None):  # pylint: disable=unused-argument
        calls.append(url)
        if fail:
            raise urllib.error.URLError("down")
        names = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["arg[]"]
        results = [{"Name": n, "PackageBase": n.split("-client")[0], "Version": "1-1"}
                   for n in names]
        return io.BytesIO(json.dumps({"results": results}).encode())
    return opener


def test_fetch_info_batches(monkeypatch):
    """250 names take three requests, not 250."""
    calls = []
    monkeypatch.setattr(aur.urllib.request, "urlopen", _fake_urlopen(calls))
    got = aur.fetch_info([f"p{i}" for i in range(250)])
    assert len(calls) == 3 and len(got) == 250


def test_split_child_resolves_to_pkgbase(monkeypatch):
    """freeipa-client is fetched from the freeipa repo."""
    monkeypatch.setattr(aur.urllib.request, "urlopen", _fake_urlopen([]))
    meta = aur.fetch_info(["freeipa-client"])
    assert aur.pkgbase("freeipa-client", None, meta) == "freeipa"
    assert aur.git_url("freeipa-client", None, meta).endswith("/freeipa.git")
    assert aur.git_url("pac", "https://g/pac.git", meta) == "https://g/pac.git"


# pylint: disable-next=unused-argument
def test_refresh_meta_keeps_previous_on_outage(dirs, monkeypatch):
    """An RPC outage reuses the saved pkgbase instead of guessing."""
    cfg.AUR_META.write_text(json.dumps({"freeipa-client": {"pkgbase": "freeipa"}}),
                            encoding="utf-8")
    monkeypatch.setattr(aur.urllib.request, "urlopen", _fake_urlopen([], fail=True))
    meta = aur.refresh_meta([{"name": "freeipa-client"}, {"name": "pac", "source": "x"}])
    assert meta == {"freeipa-client": {"pkgbase": "freeipa"}}
