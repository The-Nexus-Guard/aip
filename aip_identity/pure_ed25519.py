"""
Pure Python Ed25519 Implementation

Vendored from python-pure25519 (https://github.com/warner/python-pure25519)
License: MIT

This is a pure Python implementation of Ed25519 signatures.
It's slower than PyNaCl/libsodium but has no dependencies.
"""

import binascii
import hashlib
import os

# Curve constants
Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493

def inv(x):
    return pow(x, Q-2, Q)

d = -121665 * inv(121666)
I = pow(2, (Q-1)//4, Q)

def xrecover(y):
    xx = (y*y-1) * inv(d*y*y+1)
    x = pow(xx, (Q+3)//8, Q)
    if (x*x - xx) % Q != 0:
        x = (x*I) % Q
    if x % 2 != 0:
        x = Q-x
    return x

By = 4 * inv(5)
Bx = xrecover(By)
B = [Bx % Q, By % Q]

def xform_affine_to_extended(pt):
    (x, y) = pt
    return (x % Q, y % Q, 1, (x*y) % Q)

def xform_extended_to_affine(pt):
    (x, y, z, _) = pt
    return ((x*inv(z)) % Q, (y*inv(z)) % Q)

def double_element(pt):
    (X1, Y1, Z1, _) = pt
    A = (X1*X1)
    B = (Y1*Y1)
    C = (2*Z1*Z1)
    D = (-A) % Q
    J = (X1+Y1) % Q
    E = (J*J-A-B) % Q
    G = (D+B) % Q
    F = (G-C) % Q
    H = (D-B) % Q
    X3 = (E*F) % Q
    Y3 = (G*H) % Q
    Z3 = (F*G) % Q
    T3 = (E*H) % Q
    return (X3, Y3, Z3, T3)

def add_elements(pt1, pt2):
    (X1, Y1, Z1, T1) = pt1
    (X2, Y2, Z2, T2) = pt2
    A = ((Y1-X1)*(Y2-X2)) % Q
    B = ((Y1+X1)*(Y2+X2)) % Q
    C = T1*(2*d)*T2 % Q
    D = Z1*2*Z2 % Q
    E = (B-A) % Q
    F = (D-C) % Q
    G = (D+C) % Q
    H = (B+A) % Q
    X3 = (E*F) % Q
    Y3 = (G*H) % Q
    T3 = (E*H) % Q
    Z3 = (F*G) % Q
    return (X3, Y3, Z3, T3)

def scalarmult(pt, n):
    if n == 0:
        return xform_affine_to_extended((0, 1))
    result = double_element(scalarmult(pt, n >> 1))
    if n & 1:
        result = add_elements(result, pt)
    return result

def encodepoint(P):
    x, y = P
    assert 0 <= y < (1 << 255)
    if x & 1:
        y += 1 << 255
    return binascii.unhexlify("%064x" % y)[::-1]

def decodepoint(s):
    unclamped = int(binascii.hexlify(s[:32][::-1]), 16)
    clamp = (1 << 255) - 1
    y = unclamped & clamp
    x = xrecover(y)
    if bool(x & 1) != bool(unclamped & (1 << 255)):
        x = Q - x
    return [x, y]

def bytes_to_scalar(s):
    return int(binascii.hexlify(s[::-1]), 16)

def scalar_to_bytes(n):
    return binascii.unhexlify("%064x" % n)[::-1]

def clamp_scalar(s):
    a = bytes_to_scalar(s)
    a &= (1 << 254) - 1 - 7
    a |= (1 << 254)
    return a

# EdDSA functions

def create_keypair():
    """Generate a new Ed25519 keypair."""
    seed = os.urandom(32)
    return seed, get_public_key(seed)

def get_public_key(secret_key):
    """Derive public key from secret key (seed)."""
    h = hashlib.sha512(secret_key).digest()
    a = clamp_scalar(h[:32])
    A = scalarmult(xform_affine_to_extended(B), a)
    return encodepoint(xform_extended_to_affine(A))

def sign(secret_key, message):
    """Sign a message with the secret key."""
    if isinstance(message, str):
        message = message.encode('utf-8')

    h = hashlib.sha512(secret_key).digest()
    a = clamp_scalar(h[:32])

    public_key = get_public_key(secret_key)

    # r = H(h[32:64] || message)
    r_hash = hashlib.sha512(h[32:64] + message).digest()
    r = bytes_to_scalar(r_hash) % L

    # R = r * B
    R = scalarmult(xform_affine_to_extended(B), r)
    R_bytes = encodepoint(xform_extended_to_affine(R))

    # S = (r + H(R || A || message) * a) mod L
    h_ram = hashlib.sha512(R_bytes + public_key + message).digest()
    h_ram_scalar = bytes_to_scalar(h_ram) % L
    S = (r + h_ram_scalar * a) % L

    return R_bytes + scalar_to_bytes(S)

def verify(public_key, message, signature):
    """Verify a signature."""
    if isinstance(message, str):
        message = message.encode('utf-8')

    if len(signature) != 64:
        return False

    R_bytes = signature[:32]
    S_bytes = signature[32:64]

    try:
        R = decodepoint(R_bytes)
        A = decodepoint(public_key)
    except:
        return False

    S = bytes_to_scalar(S_bytes)
    if S >= L:
        return False

    # Check: S * B == R + H(R || A || message) * A
    h = hashlib.sha512(R_bytes + public_key + message).digest()
    h_scalar = bytes_to_scalar(h) % L

    # Left side: S * B
    left = scalarmult(xform_affine_to_extended(B), S)
    left_point = xform_extended_to_affine(left)

    # Right side: R + h * A
    hA = scalarmult(xform_affine_to_extended(A), h_scalar)
    right = add_elements(xform_affine_to_extended(R), hA)
    right_point = xform_extended_to_affine(right)

    return encodepoint(left_point) == encodepoint(right_point)


# Convenience class for AIP integration
class Ed25519Key:
    """Simple wrapper for Ed25519 operations."""

    def __init__(self, secret_key=None):
        if secret_key is None:
            self.secret_key, self.public_key = create_keypair()
        else:
            self.secret_key = secret_key
            self.public_key = get_public_key(secret_key)

    @classmethod
    def generate(cls):
        """Generate a new keypair."""
        return cls()

    @classmethod
    def from_seed(cls, seed):
        """Create from existing seed (32 bytes)."""
        if isinstance(seed, str):
            seed = bytes.fromhex(seed)
        assert len(seed) == 32
        return cls(seed)

    def sign(self, message):
        """Sign a message."""
        return sign(self.secret_key, message)

    def verify(self, message, signature):
        """Verify a signature (can also use class method with just public key)."""
        return verify(self.public_key, message, signature)

    @staticmethod
    def verify_with_public_key(public_key, message, signature):
        """Verify using just a public key."""
        return verify(public_key, message, signature)

    def public_key_hex(self):
        """Get public key as hex string."""
        return self.public_key.hex()

    def secret_key_hex(self):
        """Get secret key (seed) as hex string."""
        return self.secret_key.hex()


def selftest():
    """Run basic self-test."""
    # Generate keypair
    key = Ed25519Key.generate()
    print(f"Generated keypair:")
    print(f"  Public key: {key.public_key_hex()[:32]}...")
    print(f"  Secret key: {key.secret_key_hex()[:32]}...")

    # Sign a message
    message = b"Hello, AIP!"
    signature = key.sign(message)
    print(f"\nSigned message: {message}")
    print(f"  Signature: {signature.hex()[:32]}...")

    # Verify
    valid = key.verify(message, signature)
    print(f"  Valid: {valid}")

    # Verify with wrong message should fail
    wrong_valid = key.verify(b"Wrong message", signature)
    print(f"  Wrong message valid: {wrong_valid}")

    assert valid == True
    assert wrong_valid == False
    print("\nSelf-test passed!")


if __name__ == "__main__":
    selftest()
