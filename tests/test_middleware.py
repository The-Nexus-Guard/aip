"""
Tests for the AIP middleware module.
"""

import base64
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from nacl.signing import SigningKey

from aip_identity.middleware import AIPMiddleware, AIPIdentity


@pytest.fixture
def mock_client():
    """Create a mock AIPClient."""
    sk = SigningKey.generate()

    client = MagicMock()
    client.did = "did:aip:test123"
    client.public_key = base64.b64encode(sk.verify_key.encode()).decode()
    client.DEFAULT_SERVICE = "https://aip-service.fly.dev"
    client._signing_key = sk

    def sign_side_effect(message):
        sig = sk.sign(message.encode()).signature
        return base64.b64encode(sig).decode()

    client.sign.side_effect = sign_side_effect

    def verify_side_effect(did, message, signature):
        if did != "did:aip:test123":
            return False
        try:
            sig_bytes = base64.b64decode(signature)
            sk.verify_key.verify(message.encode(), sig_bytes)
            return True
        except Exception:
            return False

    client.verify_signature.side_effect = verify_side_effect
    client.get_trust_score.return_value = 0.75
    client.resolve.return_value = {
        "did": "did:aip:test123",
        "public_key": client.public_key,
        "trust_score": 0.75,
        "platform": "test",
    }

    return client


@pytest.fixture
def middleware(mock_client):
    """Create middleware from a mock client."""
    return AIPMiddleware.from_client(mock_client)


class TestAIPIdentity:
    def test_identity_repr(self):
        identity = AIPIdentity(
            did="did:aip:abc", public_key="pk", trust_score=0.5, verified=True
        )
        assert "did:aip:abc" in repr(identity)
        assert "0.5" in repr(identity)

    def test_identity_bool_verified(self):
        identity = AIPIdentity(did="did:aip:abc", public_key="pk", verified=True)
        assert bool(identity) is True

    def test_identity_bool_unverified(self):
        identity = AIPIdentity(did="did:aip:abc", public_key="pk", verified=False)
        assert bool(identity) is False


class TestMiddlewareInit:
    def test_from_client(self, mock_client):
        mw = AIPMiddleware.from_client(mock_client)
        assert mw.did == "did:aip:test123"

    def test_from_client_with_options(self, mock_client):
        mw = AIPMiddleware.from_client(
            mock_client, verify_peers=False, min_trust_score=0.5
        )
        assert mw.verify_peers is False
        assert mw.min_trust_score == 0.5

    def test_client_property_raises_if_none(self):
        mw = AIPMiddleware.__new__(AIPMiddleware)
        mw._client = None
        mw.verify_peers = True
        mw.min_trust_score = 0.0
        with pytest.raises(RuntimeError, match="not initialized"):
            _ = mw.client


class TestRequestSigning:
    def test_sign_request_returns_headers(self, middleware):
        headers = middleware.sign_request("GET", "/api/data")
        assert AIPMiddleware.HEADER_DID in headers
        assert AIPMiddleware.HEADER_SIGNATURE in headers
        assert AIPMiddleware.HEADER_TIMESTAMP in headers
        assert AIPMiddleware.HEADER_NONCE in headers

    def test_sign_request_includes_did(self, middleware):
        headers = middleware.sign_request("GET", "/api/data")
        assert headers[AIPMiddleware.HEADER_DID] == "did:aip:test123"

    def test_sign_request_with_body(self, middleware):
        headers = middleware.sign_request("POST", "/api/submit", body='{"key": "value"}')
        assert headers[AIPMiddleware.HEADER_SIGNATURE]

    def test_sign_request_custom_timestamp(self, middleware):
        ts = "2026-03-11T08:00:00+00:00"
        headers = middleware.sign_request("GET", "/api/data", timestamp=ts)
        assert headers[AIPMiddleware.HEADER_TIMESTAMP] == ts

    def test_different_methods_different_signatures(self, middleware):
        h1 = middleware.sign_request("GET", "/api/data")
        h2 = middleware.sign_request("POST", "/api/data")
        assert h1[AIPMiddleware.HEADER_SIGNATURE] != h2[AIPMiddleware.HEADER_SIGNATURE]


class TestRequestVerification:
    def test_verify_valid_request(self, middleware):
        # Sign a request
        headers = middleware.sign_request("GET", "/api/data")
        # Verify it
        identity = middleware.verify_request(
            headers, method="GET", path="/api/data"
        )
        assert identity.did == "did:aip:test123"
        assert identity.verified is True
        assert identity.trust_score == 0.75

    def test_verify_missing_headers(self, middleware):
        identity = middleware.verify_request({})
        assert identity.verified is False

    def test_verify_expired_timestamp(self, middleware):
        old_ts = (datetime.now(tz=timezone.utc) - timedelta(minutes=10)).isoformat()
        headers = middleware.sign_request("GET", "/api/data", timestamp=old_ts)
        identity = middleware.verify_request(
            headers, method="GET", path="/api/data", max_age_seconds=300
        )
        assert identity.verified is False

    def test_verify_invalid_signature(self, middleware):
        headers = middleware.sign_request("GET", "/api/data")
        headers[AIPMiddleware.HEADER_SIGNATURE] = base64.b64encode(b"x" * 64).decode()
        identity = middleware.verify_request(
            headers, method="GET", path="/api/data"
        )
        assert identity.verified is False

    def test_verify_case_insensitive_headers(self, middleware):
        headers = middleware.sign_request("GET", "/api/data")
        # Lowercase all headers
        lower_headers = {k.lower(): v for k, v in headers.items()}
        identity = middleware.verify_request(
            lower_headers, method="GET", path="/api/data"
        )
        assert identity.did == "did:aip:test123"


class TestTrustAndDiscovery:
    def test_trust_score(self, middleware):
        score = middleware.trust_score("did:aip:test123")
        assert score == 0.75

    def test_trust_score_error_returns_zero(self, middleware):
        middleware.client.get_trust_score.side_effect = Exception("network error")
        score = middleware.trust_score("did:aip:unknown")
        assert score == 0.0

    def test_discover_peers(self, middleware):
        middleware.client.search_agents.return_value = [
            {"did": "did:aip:a", "trust_score": 0.8},
            {"did": "did:aip:b", "trust_score": 0.2},
        ]
        peers = middleware.discover_peers(min_trust=0.5)
        assert len(peers) == 1
        assert peers[0]["did"] == "did:aip:a"

    def test_discover_peers_no_filter(self, middleware):
        middleware.client.search_agents.return_value = [
            {"did": "did:aip:a"},
            {"did": "did:aip:b"},
        ]
        peers = middleware.discover_peers()
        assert len(peers) == 2


class TestMessaging:
    def test_send_message(self, middleware):
        middleware.client.send_message.return_value = True
        assert middleware.send_message("did:aip:other", "hello") is True

    def test_send_message_failure(self, middleware):
        middleware.client.send_message.side_effect = Exception("network")
        assert middleware.send_message("did:aip:other", "hello") is False

    def test_get_messages(self, middleware):
        middleware.client.get_messages.return_value = [
            {"from": "did:aip:a", "content": "hi"}
        ]
        msgs = middleware.get_messages()
        assert len(msgs) == 1
