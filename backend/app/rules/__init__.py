"""Rule engine: runs every registered rule and collects RedFlags."""

from collections.abc import Callable

from app.models import Entity, Offer, RedFlag
from app.rules.core import fee_demand, free_mail_sender, off_platform_contact, task_for_pay, urgency

Rule = Callable[[Offer, list[Entity]], list[RedFlag]]

RULES: list[Rule] = [
    fee_demand,
    task_for_pay,
    off_platform_contact,
    free_mail_sender,
    urgency,
]


def run_rules(offer: Offer, entities: list[Entity]) -> list[RedFlag]:
    flags: list[RedFlag] = []
    for rule in RULES:
        flags.extend(rule(offer, entities))
    return flags
