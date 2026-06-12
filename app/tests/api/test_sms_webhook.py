"""
Tests for the inbound SMS webhook (HELP / STOP keywords).

STOP opts the user out (sms_opt_in=False, SMS channel disabled) and the user
can re-opt-in via POST /auth/sms-opt-in — repeatedly. HELP replies with the
sender's current alert status.
"""
import pytest
from unittest.mock import AsyncMock, patch

from app.models import IncomingMessage


SMS_WEBHOOK_URL = "/api/v1/webhooks/sms/incoming"
OPT_IN_URL = "/api/v1/auth/sms-opt-in"


@pytest.fixture
def valid_signature():
    """Bypass Twilio signature validation (tested separately)."""
    with patch("app.api.webhooks.validate_twilio_request", new=AsyncMock(return_value=True)):
        yield


def _send_sms(client, from_number, body):
    return client.post(SMS_WEBHOOK_URL, data={"From": from_number, "Body": body})


class TestSmsStopKeyword:

    def test_stop_opts_user_out(self, client, test_user, db_session, valid_signature):
        test_user.sms_opt_in = True
        test_user.preferred_channels = ["sms", "email"]
        db_session.commit()

        response = _send_sms(client, test_user.phone, "STOP")

        assert response.status_code == 200
        assert "unsubscribed" in response.text.lower()
        db_session.refresh(test_user)
        assert test_user.sms_opt_in is False
        assert test_user.sms_opt_in_at is not None
        assert "sms" not in (test_user.preferred_channels or [])

    @pytest.mark.parametrize("keyword", ["stop", "Stop", " STOP ", "UNSUBSCRIBE", "CANCEL", "END", "QUIT", "STOPALL"])
    def test_stop_keyword_variants(self, client, test_user, db_session, valid_signature, keyword):
        test_user.sms_opt_in = True
        db_session.commit()

        response = _send_sms(client, test_user.phone, keyword)

        assert response.status_code == 200
        db_session.refresh(test_user)
        assert test_user.sms_opt_in is False

    def test_stop_from_unknown_number(self, client, db_session, valid_signature):
        response = _send_sms(client, "+19998887777", "STOP")
        assert response.status_code == 200
        assert "no more messages" in response.text.lower()

    def test_stop_then_re_opt_in_then_stop_again(
        self, authenticated_client, test_user, db_session, valid_signature
    ):
        """The opt-out / opt-in loop can repeat indefinitely."""
        # Arm CSRF for the authenticated opt-in calls
        authenticated_client.get("/api/v1/auth/me")
        token = authenticated_client.cookies.get("csrf_token")
        if token:
            authenticated_client.headers.update({"X-CSRF-Token": token})

        for _ in range(2):
            # Opt in via the Preferences popup endpoint
            r = authenticated_client.post(
                OPT_IN_URL,
                json={"accepted": True, "phone": "5551230000", "consent": True},
            )
            assert r.status_code == 200
            db_session.refresh(test_user)
            assert test_user.sms_opt_in is True
            assert "sms" in test_user.preferred_channels

            # Text STOP — opts back out
            r = _send_sms(authenticated_client, "+15551230000", "STOP")
            assert r.status_code == 200
            db_session.refresh(test_user)
            assert test_user.sms_opt_in is False
            assert "sms" not in (test_user.preferred_channels or [])


class TestSmsHelpKeyword:

    def test_help_when_opted_in(self, client, test_user, db_session, valid_signature):
        test_user.sms_opt_in = True
        db_session.commit()

        response = _send_sms(client, test_user.phone, "HELP")

        assert response.status_code == 200
        assert "currently receiving" in response.text.lower()
        assert "stop" in response.text.lower()
        # HELP must not change the opt-in state
        db_session.refresh(test_user)
        assert test_user.sms_opt_in is True

    def test_help_when_not_opted_in(self, client, test_user, db_session, valid_signature):
        test_user.sms_opt_in = False
        db_session.commit()

        response = _send_sms(client, test_user.phone, "HELP")

        assert response.status_code == 200
        assert "not currently receiving" in response.text.lower()

    def test_help_from_unknown_number(self, client, valid_signature):
        response = _send_sms(client, "+19998887777", "INFO")
        assert response.status_code == 200
        assert "not currently receiving" in response.text.lower()


class TestSmsWebhookGeneral:

    def test_invalid_signature_rejected(self, client):
        with patch("app.api.webhooks.validate_twilio_request", new=AsyncMock(return_value=False)):
            response = _send_sms(client, "+15551234567", "STOP")
        assert response.status_code == 401

    def test_non_keyword_message_recorded_without_reply(
        self, client, test_user, db_session, valid_signature
    ):
        response = _send_sms(client, test_user.phone, "Thanks, got the alert!")

        assert response.status_code == 200
        assert "<Message>" not in response.text
        msg = (
            db_session.query(IncomingMessage)
            .filter(IncomingMessage.from_number == test_user.phone)
            .order_by(IncomingMessage.id.desc())
            .first()
        )
        assert msg is not None
        assert msg.body == "Thanks, got the alert!"
        assert msg.user_id == test_user.id
        assert msg.is_processed is False
