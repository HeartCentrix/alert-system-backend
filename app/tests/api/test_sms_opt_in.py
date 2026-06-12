"""
Tests for the SMS text-alert opt-in flow (Settings → Preferences popup).

Covers POST /api/v1/auth/sms-opt-in (accept / decline / conflicts), the
sms_opt_in flag exposure on /auth/me, and the preferred-channels guard on
PUT /auth/me for declined users.
"""
import pytest

from app.models import User


OPT_IN_URL = "/api/v1/auth/sms-opt-in"
ME_URL = "/api/v1/auth/me"


def _arm_csrf(test_client, bootstrap_url=ME_URL):
    """GET once so the CSRF cookie exists, then echo it as the header."""
    test_client.get(bootstrap_url)
    token = test_client.cookies.get("csrf_token")
    if token:
        test_client.headers.update({"X-CSRF-Token": token})
    return test_client


@pytest.fixture
def opt_in_client(authenticated_client):
    """Authenticated client with the CSRF cookie/header round-trip done."""
    return _arm_csrf(authenticated_client)


class TestSmsOptInEndpoint:
    """Test POST /api/v1/auth/sms-opt-in."""

    def test_requires_auth(self, client):
        _arm_csrf(client, "/api/v1/auth/providers")
        response = client.post(OPT_IN_URL, json={"accepted": True, "phone": "5551234567", "consent": True})
        assert response.status_code == 401

    def test_accept_stores_phone_and_flag(self, opt_in_client, test_user, db_session):
        response = opt_in_client.post(
            OPT_IN_URL,
            json={"accepted": True, "phone": "(555) 123-4567", "consent": True},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["sms_opt_in"] is True
        # Stored normalized to E.164 for Twilio
        assert data["phone"] == "+15551234567"
        # Accepting enables the SMS notification channel in the same step
        assert "sms" in (data["preferred_channels"] or [])

        db_session.refresh(test_user)
        assert test_user.sms_opt_in is True
        assert test_user.sms_opt_in_at is not None
        assert test_user.phone == "+15551234567"

    def test_accept_replaces_existing_phone(self, opt_in_client, test_user, db_session):
        # test_user fixture already has phone +1234567890
        assert test_user.phone == "+1234567890"
        response = opt_in_client.post(
            OPT_IN_URL,
            json={"accepted": True, "phone": "5559876543", "consent": True},
        )
        assert response.status_code == 200
        db_session.refresh(test_user)
        assert test_user.phone == "+15559876543"
        assert test_user.sms_opt_in is True

    def test_accept_without_consent_rejected(self, opt_in_client, test_user, db_session):
        response = opt_in_client.post(
            OPT_IN_URL,
            json={"accepted": True, "phone": "5551234567", "consent": False},
        )
        assert response.status_code == 422
        db_session.refresh(test_user)
        assert test_user.sms_opt_in is None

    def test_accept_with_invalid_phone_rejected(self, opt_in_client):
        response = opt_in_client.post(
            OPT_IN_URL,
            json={"accepted": True, "phone": "12345", "consent": True},
        )
        assert response.status_code == 422

    def test_accept_with_missing_phone_rejected(self, opt_in_client):
        response = opt_in_client.post(
            OPT_IN_URL,
            json={"accepted": True, "consent": True},
        )
        assert response.status_code == 422

    def test_international_number_with_country_code_kept(self, opt_in_client, test_user, db_session):
        response = opt_in_client.post(
            OPT_IN_URL,
            json={"accepted": True, "phone": "+44 7911 123456", "consent": True},
        )
        assert response.status_code == 200
        db_session.refresh(test_user)
        assert test_user.phone == "+447911123456"

    def test_eleven_digit_us_number_normalized(self, opt_in_client, test_user, db_session):
        response = opt_in_client.post(
            OPT_IN_URL,
            json={"accepted": True, "phone": "1-555-987-1111", "consent": True},
        )
        assert response.status_code == 200
        db_session.refresh(test_user)
        assert test_user.phone == "+15559871111"

    def test_phone_of_another_user_conflicts(self, opt_in_client, db_session):
        other = User(
            email="other-phone-owner@example.com",
            hashed_password="hashed",
            first_name="Other",
            last_name="Owner",
            phone="5550001111",
        )
        db_session.add(other)
        db_session.commit()

        response = opt_in_client.post(
            OPT_IN_URL,
            json={"accepted": True, "phone": "5550001111", "consent": True},
        )
        assert response.status_code == 409

    def test_decline_records_flag_and_strips_sms_channel(self, opt_in_client, test_user, db_session):
        test_user.preferred_channels = ["sms", "email"]
        db_session.commit()

        response = opt_in_client.post(OPT_IN_URL, json={"accepted": False})
        assert response.status_code == 200
        data = response.json()
        assert data["sms_opt_in"] is False
        assert "sms" not in (data["preferred_channels"] or [])

        db_session.refresh(test_user)
        assert test_user.sms_opt_in is False
        assert test_user.sms_opt_in_at is not None
        assert "sms" not in (test_user.preferred_channels or [])

    def test_accept_enables_sms_channel(self, opt_in_client, test_user, db_session):
        test_user.preferred_channels = ["email"]
        db_session.commit()

        response = opt_in_client.post(
            OPT_IN_URL,
            json={"accepted": True, "phone": "5556667777", "consent": True},
        )
        assert response.status_code == 200
        assert "sms" in response.json()["preferred_channels"]

    def test_declined_user_can_re_opt_in(self, opt_in_client):
        opt_in_client.post(OPT_IN_URL, json={"accepted": False})

        response = opt_in_client.post(
            OPT_IN_URL,
            json={"accepted": True, "phone": "5557778888", "consent": True},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["sms_opt_in"] is True
        assert "sms" in data["preferred_channels"]

    def test_me_exposes_sms_opt_in(self, opt_in_client):
        # Before any decision the flag is null so the SPA shows the popup
        response = opt_in_client.get(ME_URL)
        assert response.status_code == 200
        assert response.json()["sms_opt_in"] is None

        opt_in_client.post(
            OPT_IN_URL, json={"accepted": True, "phone": "5552223333", "consent": True}
        )
        response = opt_in_client.get(ME_URL)
        assert response.json()["sms_opt_in"] is True


class TestDeclinedUserChannelGuard:
    """Declined users cannot select SMS as a preferred channel."""

    def test_declined_user_cannot_select_sms_channel(self, opt_in_client, test_user, db_session):
        opt_in_client.post(OPT_IN_URL, json={"accepted": False})

        response = opt_in_client.put(
            ME_URL, json={"preferred_channels": ["sms", "email"]}
        )
        assert response.status_code == 400
        assert "declined" in response.json()["detail"].lower()

    def test_declined_user_can_select_other_channels(self, opt_in_client):
        opt_in_client.post(OPT_IN_URL, json={"accepted": False})

        response = opt_in_client.put(
            ME_URL, json={"preferred_channels": ["email", "voice"]}
        )
        assert response.status_code == 200

    def test_opted_in_user_can_select_sms_channel(self, opt_in_client):
        opt_in_client.post(
            OPT_IN_URL, json={"accepted": True, "phone": "5554445555", "consent": True}
        )

        response = opt_in_client.put(
            ME_URL, json={"preferred_channels": ["sms", "email"]}
        )
        assert response.status_code == 200
