"""Domain lists and helpers shared by detectors."""

FREEMAIL_DOMAINS = frozenset(
    {
        "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "ymail.com",
        "outlook.com", "hotmail.com", "live.com", "msn.com", "rediffmail.com",
        "icloud.com", "aol.com", "protonmail.com", "proton.me", "zoho.com", "zohomail.com",
        "zohomail.in", "gmx.com", "mail.com", "yandex.com",
    }
)  # fmt: skip

# Hiring platforms and assessment tools that send mail on behalf of real employers.
# Seeing one is neither proof of a real company nor a sign of impersonation.
HIRING_PLATFORM_DOMAINS = frozenset(
    {
        "myworkday.com", "myworkdayjobs.com", "greenhouse.io", "lever.co",
        "smartrecruiters.com", "successfactors.com", "successfactors.eu", "taleo.net",
        "icims.com", "eightfold.ai", "darwinbox.in", "keka.com", "zohorecruit.com",
        "naukri.com", "linkedin.com", "indeed.com", "foundit.in", "instahyre.com",
        "internshala.com", "unstop.com", "joinsuperset.com", "hirepro.in", "mettl.com",
        "hackerrank.com", "hackerearth.com", "aspiringminds.com", "shl.com", "cocubes.com",
    }
)  # fmt: skip


def is_under(domain: str, parents: frozenset[str] | set[str] | list[str]) -> bool:
    """True if `domain` equals one of `parents` or is a subdomain of one."""
    return any(domain == p or domain.endswith("." + p) for p in parents)
