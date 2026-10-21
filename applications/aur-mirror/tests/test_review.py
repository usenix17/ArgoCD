"""Claude review: risk gating, transient errors and the circuit breaker."""
import types

import pytest

from aurmirror import config as cfg
from aurmirror import review
from aurmirror.recipe import RecipeText

RECIPE = RecipeText("--- PKGBUILD ---\npkgname=x\n", False, [])


class FakeAPIError(Exception):
    """Base of the fake SDK's errors."""


class FakeBadRequest(FakeAPIError):
    """400."""


class FakeAuth(FakeAPIError):
    """401."""


class FakePermission(FakeAPIError):
    """403."""


def fake_sdk(outcomes):
    """Fake anthropic module: each create() pops a verdict dict, None, or an exception."""
    calls = []

    class Messages:  # pylint: disable=too-few-public-methods
        """messages.create stand-in."""

        def create(self, **kwargs):
            """Return the next scripted outcome."""
            calls.append(kwargs)
            out = outcomes.pop(0)
            if isinstance(out, Exception):
                raise out
            blocks = [] if out is None else [types.SimpleNamespace(type="tool_use", input=out)]
            return types.SimpleNamespace(content=blocks)

    class Client:  # pylint: disable=too-few-public-methods
        """Anthropic client stand-in."""

        def __init__(self, **_):
            self.messages = Messages()

    sdk = types.SimpleNamespace(Anthropic=Client, APIError=FakeAPIError,
                                BadRequestError=FakeBadRequest, AuthenticationError=FakeAuth,
                                PermissionDeniedError=FakePermission)
    return sdk, calls


@pytest.fixture(name="sdk")
def fixture_sdk(monkeypatch):
    """Install a scripted fake SDK; returns a function taking the outcome list."""
    monkeypatch.setattr(cfg, "ANTHROPIC_API_KEY", "k")
    monkeypatch.setattr(cfg, "ESCALATION_PASSES", 1)

    def install(outcomes):
        mod, calls = fake_sdk(list(outcomes))
        monkeypatch.setattr(review, "anthropic", mod)
        return calls
    return install


def test_medium_risk_clears(sdk):
    """The escalated lane gates on risk, not the biased safe flag."""
    sdk([{"safe": False, "risk": "medium", "summary": "nitpick"}])
    assert review.Reviewer().escalated("x", RECIPE, None)["safe"] is True


def test_high_risk_holds(sdk):
    """High risk holds even when safe=true."""
    sdk([{"safe": True, "risk": "high", "summary": "curl|bash added"}])
    got = review.Reviewer().escalated("x", RECIPE, None)
    assert got["safe"] is False and not got.get("transient")


def test_missing_key_is_transient(monkeypatch):
    """No key is an infrastructure problem, not a security verdict."""
    monkeypatch.setattr(cfg, "ANTHROPIC_API_KEY", "")
    got = review.Reviewer().quick("x", RECIPE)
    assert got["transient"] and got["risk"] == "error"


def test_api_error_is_transient(sdk):
    """A rate limit or network error retries next run."""
    sdk([FakeAPIError("overloaded")])
    assert review.Reviewer().quick("x", RECIPE)["transient"]


def test_credit_error_trips_breaker(sdk):
    """After a credit error the run stops calling the API."""
    calls = sdk([FakeBadRequest("Your credit balance is too low"), {"risk": "low"}])
    rev = review.Reviewer()
    assert rev.quick("a", RECIPE)["transient"]
    assert rev.tripped
    second = rev.quick("b", RECIPE)
    assert second["transient"] and "skipped" in second["summary"]
    assert len(calls) == 1


def test_no_verdict_retries_then_fails_closed(sdk):
    """A missing tool call is retried once, then held (not retried forever)."""
    calls = sdk([None, None])
    got = review.Reviewer().quick("x", RECIPE)
    assert got["safe"] is False and not got.get("transient") and len(calls) == 2


def test_no_verdict_recovers_on_retry(sdk):
    """A second attempt that answers is used."""
    sdk([None, {"safe": True, "risk": "low", "summary": "ok"}])
    assert review.Reviewer().quick("x", RECIPE)["safe"] is True


def test_partial_recipe_is_disclosed(sdk):
    """The reviewer is told what it was not shown."""
    calls = sdk([{"safe": True, "risk": "low", "summary": "ok"}])
    partial = RecipeText("x", True, ["blob.bin (binary)"])
    review.Reviewer().escalated("x", partial, None)
    assert "blob.bin (binary)" in calls[0]["messages"][0]["content"]
