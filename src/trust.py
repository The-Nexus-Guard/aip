"""
Agent Identity Protocol - Trust Layer

Provides vouching and trust calculation for agent-to-agent trust networks.
Works on top of the identity layer - trust requires verified identity.

Key concepts:
- Vouch: A signed statement "I trust agent X for scope Y"
- Trust Graph: Each agent maintains their own view of who trusts whom
- Trust Path: Chain of vouches from you to a target agent (isnad chain)
- Trust Level: How much to trust based on path length and vouch strength
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, List, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import IntEnum

# Handle both package and direct imports
try:
    from .identity import AgentIdentity
except ImportError:
    from identity import AgentIdentity


class TrustLevel(IntEnum):
    """Trust levels based on relationship distance."""
    UNKNOWN = 0      # No trust path
    SUSPICIOUS = 1   # Negative vouch or revoked
    WEAK = 2         # Long path (3+ hops)
    MODERATE = 3     # Friend of friend (2 hops)
    STRONG = 4       # Direct vouch
    ULTIMATE = 5     # Self or explicitly maximum trust


class TrustScope:
    """
    Common trust scopes. Agents can define custom scopes too.

    Canonical values are UPPERCASE. Lowercase/hyphenated forms are
    accepted for backwards compatibility but deprecated.
    """
    GENERAL = "GENERAL"               # General trustworthiness
    CODE_SIGNING = "CODE_SIGNING"     # Trust to sign/deploy code
    FINANCIAL = "FINANCIAL"           # Trust for financial operations
    INFORMATION = "INFORMATION"       # Trust as information source
    IDENTITY = "IDENTITY"             # Trust to vouch for others' identity

    # Mapping from legacy lowercase/hyphenated to canonical UPPERCASE
    _LEGACY_MAP = {
        "general": "GENERAL",
        "code-signing": "CODE_SIGNING",
        "code_signing": "CODE_SIGNING",
        "financial": "FINANCIAL",
        "information": "INFORMATION",
        "identity": "IDENTITY",
    }

    @classmethod
    def normalize(cls, scope: str) -> str:
        """
        Normalize a scope value to canonical UPPERCASE form.

        Accepts legacy lowercase/hyphenated values and logs a deprecation warning.
        Returns the scope unchanged if it's already canonical or custom.
        """
        import logging
        logger = logging.getLogger("aip.trust")

        if scope in cls._LEGACY_MAP:
            canonical = cls._LEGACY_MAP[scope]
            logger.warning(
                "Deprecated trust scope '%s' used. Use '%s' instead. "
                "Legacy scope names will be removed in a future version.",
                scope, canonical
            )
            return canonical
        return scope


@dataclass
class Vouch:
    """
    A signed statement of trust from one agent to another.

    The vouch itself is signed by the voucher, making it verifiable
    and tamper-proof. This is the atomic unit of the trust network.
    """
    voucher_did: str          # Who is vouching (DID)
    voucher_pubkey: str       # Voucher's public key (for verification)
    target_did: str           # Who is being vouched for (DID)
    target_pubkey: str        # Target's public key
    scope: str                # What kind of trust
    level: TrustLevel         # How strong
    statement: str            # Human-readable statement
    created_at: str           # ISO timestamp
    expires_at: Optional[str] # Optional expiration
    signature: str = ""       # Signature over the vouch content

    def to_signable(self) -> bytes:
        """Get the canonical bytes to sign."""
        content = {
            "voucher_did": self.voucher_did,
            "target_did": self.target_did,
            "target_pubkey": self.target_pubkey,
            "scope": self.scope,
            "level": int(self.level),
            "statement": self.statement,
            "created_at": self.created_at,
            "expires_at": self.expires_at
        }
        return json.dumps(content, sort_keys=True, separators=(',', ':')).encode('utf-8')

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "voucher_did": self.voucher_did,
            "voucher_pubkey": self.voucher_pubkey,
            "target_did": self.target_did,
            "target_pubkey": self.target_pubkey,
            "scope": self.scope,
            "level": int(self.level),
            "statement": self.statement,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "signature": self.signature
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Vouch':
        """Create from dictionary."""
        return cls(
            voucher_did=data["voucher_did"],
            voucher_pubkey=data["voucher_pubkey"],
            target_did=data["target_did"],
            target_pubkey=data["target_pubkey"],
            scope=data["scope"],
            level=TrustLevel(data["level"]),
            statement=data["statement"],
            created_at=data["created_at"],
            expires_at=data.get("expires_at"),
            signature=data.get("signature", "")
        )

    @property
    def vouch_id(self) -> str:
        """Unique identifier for this vouch."""
        content = f"{self.voucher_did}:{self.target_did}:{self.scope}:{self.created_at}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def is_expired(self) -> bool:
        """Check if vouch has expired."""
        if not self.expires_at:
            return False
        expiry = datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
        return datetime.now(timezone.utc) > expiry


@dataclass
class Revocation:
    """A signed revocation of a previous vouch."""
    vouch_id: str             # ID of vouch being revoked
    revoker_did: str          # Who is revoking (must be voucher)
    revoker_pubkey: str       # Revoker's public key
    reason: str               # Why revoked
    created_at: str           # When revoked
    signature: str = ""       # Signature over revocation

    def to_signable(self) -> bytes:
        """Get the canonical bytes to sign."""
        content = {
            "vouch_id": self.vouch_id,
            "revoker_did": self.revoker_did,
            "reason": self.reason,
            "created_at": self.created_at
        }
        return json.dumps(content, sort_keys=True, separators=(',', ':')).encode('utf-8')

    def to_dict(self) -> Dict:
        return {
            "vouch_id": self.vouch_id,
            "revoker_did": self.revoker_did,
            "revoker_pubkey": self.revoker_pubkey,
            "reason": self.reason,
            "created_at": self.created_at,
            "signature": self.signature
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Revocation':
        return cls(
            vouch_id=data["vouch_id"],
            revoker_did=data["revoker_did"],
            revoker_pubkey=data["revoker_pubkey"],
            reason=data["reason"],
            created_at=data["created_at"],
            signature=data.get("signature", "")
        )


@dataclass
class TrustPath:
    """
    A chain of vouches from origin to target (isnad chain).

    Each step in the path is a verified vouch, creating an
    auditable trail of trust delegation.
    """
    origin_did: str           # Starting point (usually self)
    target_did: str           # End point
    path: List[Vouch]         # Ordered list of vouches
    scope: str                # Trust scope

    @property
    def length(self) -> int:
        """Number of hops in the path."""
        return len(self.path)

    @property
    def trust_level(self) -> TrustLevel:
        """Calculate trust level based on path length and vouch strengths."""
        if not self.path:
            return TrustLevel.UNKNOWN

        # Start with the weakest vouch level in the path
        min_level = min(v.level for v in self.path)

        # Decay based on path length
        if self.length == 1:
            return min_level  # Direct vouch
        elif self.length == 2:
            return TrustLevel(max(TrustLevel.MODERATE, min_level - 1))
        else:
            return TrustLevel(max(TrustLevel.WEAK, min_level - 2))

    def is_valid(self) -> bool:
        """Verify all vouches in the path are valid and connected."""
        if not self.path:
            return False

        # First vouch must be from origin
        if self.path[0].voucher_did != self.origin_did:
            return False

        # Last vouch must be for target
        if self.path[-1].target_did != self.target_did:
            return False

        # Each vouch's target must be the next vouch's voucher
        for i in range(len(self.path) - 1):
            if self.path[i].target_did != self.path[i + 1].voucher_did:
                return False

        # All vouches must be for the same scope (or general)
        for vouch in self.path:
            if vouch.scope != self.scope and vouch.scope != TrustScope.GENERAL:
                return False

        return True

    def to_dict(self) -> Dict:
        return {
            "origin_did": self.origin_did,
            "target_did": self.target_did,
            "scope": self.scope,
            "length": self.length,
            "trust_level": int(self.trust_level),
            "path": [v.to_dict() for v in self.path]
        }


class TrustGraph:
    """
    An agent's view of the trust network.

    Each agent maintains their own trust graph, containing:
    - Vouches they've made
    - Vouches they've received
    - Vouches they've observed from others
    - Revocations

    This is a local-first design - no central registry needed.
    """

    def __init__(self, identity: AgentIdentity):
        self.identity = identity
        self.vouches: Dict[str, Vouch] = {}           # vouch_id -> Vouch
        self.revocations: Dict[str, Revocation] = {}  # vouch_id -> Revocation
        self._by_voucher: Dict[str, Set[str]] = {}    # did -> set of vouch_ids
        self._by_target: Dict[str, Set[str]] = {}     # did -> set of vouch_ids

    @property
    def my_did(self) -> str:
        return self.identity.did

    def vouch_for(
        self,
        target: AgentIdentity,
        scope: str = TrustScope.GENERAL,
        level: TrustLevel = TrustLevel.STRONG,
        statement: str = "",
        expires_in_days: Optional[int] = None
    ) -> Vouch:
        """
        Create a signed vouch for another agent.

        This is how trust is established - you vouch for agents
        you have reason to trust.
        """
        now = datetime.now(timezone.utc)
        expires_at = None
        if expires_in_days:
            from datetime import timedelta
            expires_at = (now + timedelta(days=expires_in_days)).isoformat()

        vouch = Vouch(
            voucher_did=self.my_did,
            voucher_pubkey=self.identity.public_key,
            target_did=target.did,
            target_pubkey=target.public_key,
            scope=scope,
            level=level,
            statement=statement or f"I vouch for {target.name}",
            created_at=now.isoformat(),
            expires_at=expires_at
        )

        # Sign the vouch
        vouch.signature = self.identity.sign(vouch.to_signable())

        # Add to our graph
        self._add_vouch(vouch)

        return vouch

    def revoke_vouch(self, vouch_id: str, reason: str = "Trust revoked") -> Optional[Revocation]:
        """
        Revoke a vouch we previously made.

        Only the original voucher can revoke their vouch.
        """
        if vouch_id not in self.vouches:
            return None

        vouch = self.vouches[vouch_id]
        if vouch.voucher_did != self.my_did:
            raise ValueError("Can only revoke your own vouches")

        revocation = Revocation(
            vouch_id=vouch_id,
            revoker_did=self.my_did,
            revoker_pubkey=self.identity.public_key,
            reason=reason,
            created_at=datetime.now(timezone.utc).isoformat()
        )

        revocation.signature = self.identity.sign(revocation.to_signable())
        self.revocations[vouch_id] = revocation

        return revocation

    def _add_vouch(self, vouch: Vouch) -> None:
        """Add a vouch to the graph."""
        vid = vouch.vouch_id
        self.vouches[vid] = vouch

        if vouch.voucher_did not in self._by_voucher:
            self._by_voucher[vouch.voucher_did] = set()
        self._by_voucher[vouch.voucher_did].add(vid)

        if vouch.target_did not in self._by_target:
            self._by_target[vouch.target_did] = set()
        self._by_target[vouch.target_did].add(vid)

    def import_vouch(self, vouch: Vouch, verify: bool = True) -> bool:
        """
        Import a vouch from another agent.

        This is how trust information propagates - agents share
        their vouches with each other.
        """
        if verify:
            # Verify the signature
            valid = AgentIdentity.verify(
                vouch.voucher_pubkey,
                vouch.to_signable(),
                vouch.signature
            )
            if not valid:
                return False

        self._add_vouch(vouch)
        return True

    def import_revocation(self, revocation: Revocation, verify: bool = True) -> bool:
        """Import a revocation from another agent."""
        if verify:
            valid = AgentIdentity.verify(
                revocation.revoker_pubkey,
                revocation.to_signable(),
                revocation.signature
            )
            if not valid:
                return False

        self.revocations[revocation.vouch_id] = revocation
        return True

    def is_vouch_valid(self, vouch: Vouch) -> bool:
        """Check if a vouch is currently valid (not expired, not revoked)."""
        if vouch.is_expired():
            return False
        if vouch.vouch_id in self.revocations:
            return False
        return True

    def get_vouches_for(self, target_did: str, scope: Optional[str] = None) -> List[Vouch]:
        """Get all valid vouches for a target agent."""
        if target_did not in self._by_target:
            return []

        vouches = []
        for vid in self._by_target[target_did]:
            vouch = self.vouches[vid]
            if not self.is_vouch_valid(vouch):
                continue
            if scope and vouch.scope != scope and vouch.scope != TrustScope.GENERAL:
                continue
            vouches.append(vouch)

        return vouches

    def get_vouches_by(self, voucher_did: str, scope: Optional[str] = None) -> List[Vouch]:
        """Get all valid vouches made by an agent."""
        if voucher_did not in self._by_voucher:
            return []

        vouches = []
        for vid in self._by_voucher[voucher_did]:
            vouch = self.vouches[vid]
            if not self.is_vouch_valid(vouch):
                continue
            if scope and vouch.scope != scope and vouch.scope != TrustScope.GENERAL:
                continue
            vouches.append(vouch)

        return vouches

    def find_trust_path(
        self,
        target_did: str,
        scope: str = TrustScope.GENERAL,
        max_depth: int = 4
    ) -> Optional[TrustPath]:
        """
        Find a path of vouches from self to target.

        Uses BFS to find shortest path. This is the "isnad chain" -
        the verifiable trail of trust delegation.
        """
        if target_did == self.my_did:
            return TrustPath(self.my_did, target_did, [], scope)

        # BFS for shortest path
        from collections import deque

        queue = deque([(self.my_did, [])])
        visited = {self.my_did}

        while queue:
            current_did, path = queue.popleft()

            if len(path) >= max_depth:
                continue

            for vouch in self.get_vouches_by(current_did, scope):
                next_did = vouch.target_did

                if next_did in visited:
                    continue

                new_path = path + [vouch]

                if next_did == target_did:
                    return TrustPath(self.my_did, target_did, new_path, scope)

                visited.add(next_did)
                queue.append((next_did, new_path))

        return None

    def check_trust(
        self,
        target_did: str,
        scope: str = TrustScope.GENERAL,
        min_level: TrustLevel = TrustLevel.WEAK
    ) -> Tuple[bool, Optional[TrustPath]]:
        """
        Check if we trust a target agent.

        Returns (trusted: bool, path: TrustPath or None)
        """
        path = self.find_trust_path(target_did, scope)

        if path is None:
            return False, None

        if path.trust_level >= min_level:
            return True, path

        return False, path

    def get_trust_level(self, target_did: str, scope: str = TrustScope.GENERAL) -> TrustLevel:
        """Get trust level for a target agent."""
        path = self.find_trust_path(target_did, scope)
        if path is None:
            return TrustLevel.UNKNOWN
        return path.trust_level

    def export_vouches(self, include_received: bool = False) -> List[Dict]:
        """Export vouches for sharing with other agents."""
        vouches = []
        for vouch in self.vouches.values():
            if include_received or vouch.voucher_did == self.my_did:
                if self.is_vouch_valid(vouch):
                    vouches.append(vouch.to_dict())
        return vouches

    def export_revocations(self) -> List[Dict]:
        """Export revocations for sharing."""
        return [r.to_dict() for r in self.revocations.values()]

    def to_dict(self) -> Dict:
        """Export entire trust graph."""
        return {
            "identity": self.my_did,
            "vouches": self.export_vouches(include_received=True),
            "revocations": self.export_revocations()
        }

    @classmethod
    def from_dict(cls, data: Dict, identity: AgentIdentity) -> 'TrustGraph':
        """Import trust graph from saved data."""
        graph = cls(identity)
        for v in data.get("vouches", []):
            graph.import_vouch(Vouch.from_dict(v), verify=False)
        for r in data.get("revocations", []):
            graph.import_revocation(Revocation.from_dict(r), verify=False)
        return graph

    def save(self, filepath: str) -> None:
        """Save trust graph to file."""
        from pathlib import Path
        Path(filepath).write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, filepath: str, identity: AgentIdentity) -> 'TrustGraph':
        """Load trust graph from file."""
        from pathlib import Path
        data = json.loads(Path(filepath).read_text())
        return cls.from_dict(data, identity)


# Convenience functions

def create_trust_graph(identity: AgentIdentity) -> TrustGraph:
    """Create a new trust graph for an agent."""
    return TrustGraph(identity)


def verify_vouch(vouch: Vouch) -> bool:
    """Verify a vouch's signature."""
    return AgentIdentity.verify(
        vouch.voucher_pubkey,
        vouch.to_signable(),
        vouch.signature
    )


def verify_trust_path(path: TrustPath) -> bool:
    """Verify all signatures in a trust path."""
    if not path.is_valid():
        return False

    for vouch in path.path:
        if not verify_vouch(vouch):
            return False

    return True
