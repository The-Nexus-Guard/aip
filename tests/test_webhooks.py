"""Tests for webhook notification system."""
import base64
import hashlib
import json
import nacl.signing
import pytest
import requests


def _make_agent():
    key = nacl.signing.SigningKey.generate()
    pub = bytes(key.verify_key)
    did = f"did:aip:{hashlib.sha256(pub).hexdigest()[:32]}"
    pub_b64 = base64.b64encode(pub).decode()
    return did, pub_b64, key


def _sign(key, message):
    signed = key.sign(message.encode("utf-8"))
    return base64.b64encode(signed.signature).decode()


class TestWebhookCRUD:
    def test_create_webhook(self, local_service):
        did, pub, key = _make_agent()
        requests.post(f"{local_service}/register", json={"did": did, "public_key": pub, "platform": "test", "username": "whtest1"})

        url = "https://example.com/hook"
        sig = _sign(key, f"webhook:{url}")
        resp = requests.post(f"{local_service}/webhooks", json={
            "owner_did": did, "url": url, "events": ["registration"], "signature": sig
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["owner_did"] == did
        assert data["active"] is True

    def test_list_webhooks(self, local_service):
        did, pub, key = _make_agent()
        requests.post(f"{local_service}/register", json={"did": did, "public_key": pub, "platform": "test", "username": "whlist1"})

        url = "https://example.com/hook2"
        sig = _sign(key, f"webhook:{url}")
        requests.post(f"{local_service}/webhooks", json={"owner_did": did, "url": url, "events": ["registration"], "signature": sig})

        resp = requests.get(f"{local_service}/webhooks/{did}")
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

    def test_delete_webhook(self, local_service):
        did, pub, key = _make_agent()
        requests.post(f"{local_service}/register", json={"did": did, "public_key": pub, "platform": "test", "username": "whdel1"})

        url = "https://example.com/hook3"
        sig = _sign(key, f"webhook:{url}")
        create_resp = requests.post(f"{local_service}/webhooks", json={"owner_did": did, "url": url, "events": ["registration"], "signature": sig})
        wh_id = create_resp.json()["id"]

        del_sig = _sign(key, f"delete-webhook:{wh_id}")
        resp = requests.delete(f"{local_service}/webhooks/{wh_id}", json={"owner_did": did, "signature": del_sig})
        assert resp.status_code == 200

        list_resp = requests.get(f"{local_service}/webhooks/{did}")
        assert list_resp.json()["count"] == 0

    def test_reject_http_url(self, local_service):
        did, pub, key = _make_agent()
        requests.post(f"{local_service}/register", json={"did": did, "public_key": pub, "platform": "test", "username": "whhttp1"})

        url = "http://example.com/hook"
        sig = _sign(key, f"webhook:{url}")
        resp = requests.post(f"{local_service}/webhooks", json={"owner_did": did, "url": url, "events": ["registration"], "signature": sig})
        assert resp.status_code == 400

    def test_reject_invalid_event(self, local_service):
        did, pub, key = _make_agent()
        requests.post(f"{local_service}/register", json={"did": did, "public_key": pub, "platform": "test", "username": "whevt1"})

        url = "https://example.com/hook"
        sig = _sign(key, f"webhook:{url}")
        resp = requests.post(f"{local_service}/webhooks", json={"owner_did": did, "url": url, "events": ["bogus"], "signature": sig})
        assert resp.status_code == 400

    def test_reject_bad_signature(self, local_service):
        did, pub, key = _make_agent()
        requests.post(f"{local_service}/register", json={"did": did, "public_key": pub, "platform": "test", "username": "whbad1"})

        other_key = nacl.signing.SigningKey.generate()
        url = "https://example.com/hook"
        sig = _sign(other_key, f"webhook:{url}")
        resp = requests.post(f"{local_service}/webhooks", json={"owner_did": did, "url": url, "events": ["registration"], "signature": sig})
        assert resp.status_code == 403

    def test_max_5_webhooks(self, local_service):
        did, pub, key = _make_agent()
        requests.post(f"{local_service}/register", json={"did": did, "public_key": pub, "platform": "test", "username": "whmax1"})

        for i in range(5):
            url = f"https://example.com/hook{i}"
            sig = _sign(key, f"webhook:{url}")
            resp = requests.post(f"{local_service}/webhooks", json={"owner_did": did, "url": url, "events": ["registration"], "signature": sig})
            assert resp.status_code == 200

        url = "https://example.com/hook5"
        sig = _sign(key, f"webhook:{url}")
        resp = requests.post(f"{local_service}/webhooks", json={"owner_did": did, "url": url, "events": ["registration"], "signature": sig})
        assert resp.status_code == 400

    def test_wildcard_event(self, local_service):
        did, pub, key = _make_agent()
        requests.post(f"{local_service}/register", json={"did": did, "public_key": pub, "platform": "test", "username": "whwild1"})

        url = "https://example.com/hookall"
        sig = _sign(key, f"webhook:{url}")
        resp = requests.post(f"{local_service}/webhooks", json={"owner_did": did, "url": url, "events": ["*"], "signature": sig})
        assert resp.status_code == 200


class TestWebhookDeliveries:
    def test_delivery_log_empty(self, local_service):
        """Delivery log returns empty for webhook with no deliveries."""
        did, pub, key = _make_agent()
        reg_resp = requests.post(f"{local_service}/register", json={"did": did, "public_key": pub, "platform": "test", "username": "whdeliv1"})
        assert reg_resp.status_code == 200, f"Register failed: {reg_resp.status_code} {reg_resp.text}"
        url = "https://example.com/hook-del-empty"
        sig = _sign(key, f"webhook:{url}")
        resp = requests.post(f"{local_service}/webhooks", json={"owner_did": did, "url": url, "events": ["registration"], "signature": sig})
        assert resp.status_code == 200, f"Webhook create failed: {resp.status_code} {resp.text}"
        wh_id = resp.json()["id"]

        resp = requests.get(f"{local_service}/webhooks/{wh_id}/deliveries?owner_did={did}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["webhook_id"] == wh_id
        assert data["deliveries"] == []
        assert data["count"] == 0

    def test_delivery_log_after_fire(self, local_service):
        """Delivery logs are recorded when webhooks fire on registration."""
        import time
        did, pub, key = _make_agent()
        requests.post(f"{local_service}/register", json={"did": did, "public_key": pub, "platform": "test", "username": "whdeliv2"})

        # Create a webhook that subscribes to registration events
        url = "https://example.com/hook-delivery-test"
        sig = _sign(key, f"webhook:{url}")
        resp = requests.post(f"{local_service}/webhooks", json={"owner_did": did, "url": url, "events": ["registration"], "signature": sig})
        assert resp.status_code == 200
        wh_id = resp.json()["id"]

        # Trigger a registration event (new agent registers, webhook fires)
        did2, pub2, key2 = _make_agent()
        requests.post(f"{local_service}/register", json={"did": did2, "public_key": pub2, "platform": "test", "username": "whdeliv3"})

        # Give async webhook time to fire
        time.sleep(1)

        resp = requests.get(f"{local_service}/webhooks/{wh_id}/deliveries?owner_did={did}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["webhook_id"] == wh_id
        # Should have at least one delivery (the registration event)
        assert data["count"] >= 1
        delivery = data["deliveries"][0]
        assert "success" in delivery
        assert "event" in delivery
        assert delivery["event"] == "registration"

    def test_delivery_log_requires_owner(self, local_service):
        """Delivery log rejects requests without owner_did."""
        resp = requests.get(f"{local_service}/webhooks/fake-id/deliveries")
        assert resp.status_code == 400

    def test_delivery_log_wrong_owner(self, local_service):
        """Delivery log rejects requests from non-owner."""
        did, pub, key = _make_agent()
        requests.post(f"{local_service}/register", json={"did": did, "public_key": pub, "platform": "test", "username": "whown1"})
        url = "https://example.com/hook-own-test"
        sig = _sign(key, f"webhook:{url}")
        resp = requests.post(f"{local_service}/webhooks", json={"owner_did": did, "url": url, "events": ["registration"], "signature": sig})
        wh_id = resp.json()["id"]

        resp = requests.get(f"{local_service}/webhooks/{wh_id}/deliveries?owner_did=did:aip:wrong")
        assert resp.status_code == 403

    def test_ssrf_private_ip_rejected(self, local_service):
        """Webhook creation rejects URLs resolving to private IPs."""
        did, pub, key = _make_agent()
        requests.post(f"{local_service}/register", json={"did": did, "public_key": pub, "platform": "test", "username": "whssrf1"})
        url = "https://localhost/metadata"
        sig = _sign(key, f"webhook:{url}")
        resp = requests.post(f"{local_service}/webhooks", json={"owner_did": did, "url": url, "events": ["registration"], "signature": sig})
        assert resp.status_code == 400
        assert "private" in resp.json()["detail"].lower() or "internal" in resp.json()["detail"].lower()


class TestSSRFProtection:
    """Unit tests for SSRF protection helpers."""

    def test_private_ip_detection(self):
        from service.routes.webhooks import _is_private_ip
        assert _is_private_ip("127.0.0.1") is True
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("192.168.1.1") is True
        assert _is_private_ip("169.254.1.1") is True  # link-local
        assert _is_private_ip("224.0.0.1") is True  # multicast
        assert _is_private_ip("::1") is True  # IPv6 loopback
        assert _is_private_ip("not-an-ip") is True  # unparseable = blocked
        assert _is_private_ip("8.8.8.8") is False

    def test_safe_url_rejects_internal(self):
        from service.routes.webhooks import _is_safe_url
        assert _is_safe_url("https://localhost/hook") is False
        assert _is_safe_url("https://127.0.0.1/hook") is False
        assert _is_safe_url("") is False
