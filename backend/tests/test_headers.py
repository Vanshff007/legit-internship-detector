import pytest

from app.headers import analyze, auth_results
from app.models import DetectorStatus, Severity
from app.parser import parse_eml, parse_text


def eml(
    sender: str,
    reply_to: str | None = None,
    auth: str | None = "mx.google.com; dkim=pass; spf=pass; dmarc=pass",
    extra: str = "",
) -> bytes:
    lines = [f"From: {sender}", "To: student@example.com", "Subject: Offer"]
    if reply_to:
        lines.append(f"Reply-To: {reply_to}")
    if auth:
        lines.append(f"Authentication-Results: {auth}")
    lines += [extra] if extra else []
    return ("\n".join(lines) + "\n\nPlease find your offer attached.\n").encode()


def ids(raw: bytes) -> list[str]:
    return sorted(f.id for f in analyze(parse_eml(raw)).flags)


# --- Authentication-Results ----------------------------------------------------


def test_auth_results_parsing():
    header = (
        "mx.google.com; dkim=fail header.i=@x.com; dkim=pass header.i=@y.com; "
        "spf=softfail (google.com: domain of transitioning a@x.com) smtp.mailfrom=a@x.com; "
        "dmarc=fail (p=REJECT) header.from=x.com"
    )
    assert auth_results(header) == {"dkim": "pass", "spf": "softfail", "dmarc": "fail"}


@pytest.mark.parametrize(
    ("auth", "severity"),
    [
        ("mx.google.com; dkim=none; spf=pass; dmarc=fail", Severity.HIGH),
        ("mx.google.com; dkim=none; spf=fail; dmarc=none", Severity.HIGH),
        ("mx.google.com; dkim=pass; spf=softfail; dmarc=pass", Severity.MEDIUM),
        ("mx.google.com; dkim=fail; spf=pass; dmarc=pass", Severity.MEDIUM),
    ],
)
def test_auth_failures(auth, severity):
    [flag] = analyze(parse_eml(eml("HR <hr@company.com>", auth=auth))).flags
    assert flag.id == "H-AUTHFAIL" and flag.severity == severity


def test_auth_pass_is_clean_and_ok():
    r = analyze(parse_eml(eml("HR <hr@company.com>")))
    assert r.flags == [] and r.status == DetectorStatus.OK


def test_missing_auth_header_is_partial():
    r = analyze(parse_eml(eml("HR <hr@company.com>", auth=None)))
    assert r.status == DetectorStatus.PARTIAL and r.extra["checks"]["auth"] == "not_available"


def test_only_topmost_auth_header_is_trusted():
    # A sender can add a fake "pass" header below the real one from the receiving server.
    raw = eml(
        "HR <hr@company.com>",
        auth="mx.google.com; dkim=none; spf=fail; dmarc=fail",
        extra="Authentication-Results: fake; dkim=pass; spf=pass; dmarc=pass",
    )
    assert ids(raw) == ["H-AUTHFAIL"]


# --- Reply-To ----------------------------------------------------------------------


def test_reply_to_other_domain():
    raw = eml("Infosys Careers <careers@infosys.com>", reply_to="infosys.hr@gmail.com")
    flags = analyze(parse_eml(raw)).flags
    assert [f.id for f in flags] == ["H-REPLYTO"]
    assert flags[0].evidence == "From: careers@infosys.com → Reply-To: infosys.hr@gmail.com"


@pytest.mark.parametrize(
    "reply_to",
    [
        "talent@infosys.com",
        "campus@mail.infosys.com",  # subdomain of the same organisation
        "noreply@infosys.myworkdayjobs.com",  # hiring platform
    ],
)
def test_reply_to_same_org_or_platform_ok(reply_to):
    assert ids(eml("Infosys <careers@infosys.com>", reply_to=reply_to)) == []


# --- display name ------------------------------------------------------------------


@pytest.mark.parametrize(
    "sender",
    ["Nexa Technologies HR <nexa.hr2026@gmail.com>", "Recruitment Team <jobs.india@yahoo.com>"],
)
def test_org_name_on_free_mail(sender):
    assert ids(eml(sender)) == ["H-DISPLAYNAME"]


@pytest.mark.parametrize(
    "sender",
    [
        "Priya Sharma <priya.sharma@gmail.com>",  # a person, not an organisation
        "Nexa Technologies HR <hr@nexatech.in>",  # company domain
        "Infosys HR <infosys.hr@gmail.com>",  # known company: left to C-IMPERSONATION
    ],
)
def test_display_name_negative(sender):
    assert "H-DISPLAYNAME" not in ids(eml(sender))


def test_text_input_skipped():
    assert analyze(parse_text("hello")).status == DetectorStatus.SKIPPED
