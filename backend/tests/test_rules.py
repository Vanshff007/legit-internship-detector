import pytest

from app.extractor import extract
from app.parser import parse_text
from app.rules import run_rules


def flag_ids(text: str) -> set[str]:
    offer = parse_text(text)
    return {f.id for f in run_rules(offer, extract(offer))}


@pytest.mark.parametrize(
    "text",
    [
        "You are selected. Pay ₹1,999 registration fee to confirm your seat.",
        "A refundable security deposit of Rs. 2500 is required before joining.",
        "Kindly transfer 1500 rupees for your laptop and ID card.",
        "Training fees of INR 4999 will be deducted from your first salary.",
    ],
)
def test_fee_positive(text):
    assert "R-FEE" in flag_ids(text)


@pytest.mark.parametrize(
    "text",
    [
        "Infosys never charges any registration fee from candidates.",
        "There is no application fee for this internship.",
        "Your CTC is ₹6,00,000 per annum. Interview on Monday at 10 AM.",
    ],
)
def test_fee_negative(text):
    assert "R-FEE" not in flag_ids(text)


@pytest.mark.parametrize(
    "text",
    [
        "For further process contact HR on WhatsApp 98765 43210.",
        "Join our Telegram group for task details: t.me/earnhub123",
        "Message me on whatsapp to get your offer letter.",
    ],
)
def test_offplatform_positive(text):
    assert "R-OFFPLATFORM" in flag_ids(text)


@pytest.mark.parametrize(
    "text",
    [
        "We will never contact you on WhatsApp or Telegram.",
        "Please reply to this email to schedule your technical interview.",
    ],
)
def test_offplatform_negative(text):
    assert "R-OFFPLATFORM" not in flag_ids(text)


def test_freemail_positive():
    offer = parse_text("Send your resume to tcs.hr.recruitment@gmail.com today.")
    flags = run_rules(offer, extract(offer))
    freemail = [f for f in flags if f.id == "R-FREEMAIL"]
    assert freemail and freemail[0].evidence == "tcs.hr.recruitment@gmail.com"


def test_freemail_negative():
    assert "R-FREEMAIL" not in flag_ids("Contact campus.hiring@infosys.com for queries.")


@pytest.mark.parametrize(
    "text",
    [
        "Limited seats available, register fast.",
        "Please reply within 24 hours or the offer will be cancelled.",
        "This offer expires today.",
        "Hurry! Only 5 slots left.",
        "Only 3 seats remaining for this batch.",
    ],
)
def test_urgency_positive(text):
    assert "R-URGENCY" in flag_ids(text)


@pytest.mark.parametrize(
    "text",
    [
        "Please confirm your availability for the interview next week.",
        "The joining date is 15 July 2026.",
    ],
)
def test_urgency_negative(text):
    assert "R-URGENCY" not in flag_ids(text)


@pytest.mark.parametrize(
    "text",
    [
        "Earn ₹3000 daily by liking YouTube videos from home.",
        "Simple job: rate hotels on Google Maps and get paid ₹150 per task.",
        "Review products on Amazon and earn commission instantly.",
    ],
)
def test_taskpay_positive(text):
    assert "R-TASKPAY" in flag_ids(text)


@pytest.mark.parametrize(
    "text",
    [
        "Follow our LinkedIn page for company updates.",
        "As a QA intern you will review app features and report bugs.",
    ],
)
def test_taskpay_negative(text):
    assert "R-TASKPAY" not in flag_ids(text)


def test_genuine_offer_has_no_flags():
    text = (
        "Dear Priya, thank you for attending the technical interview on 2 September. "
        "We are pleased to offer you the role of Graduate Engineer Trainee at our Pune office. "
        "Please find the offer letter attached and contact campus.hiring@infosys.com."
    )
    assert flag_ids(text) == set()
