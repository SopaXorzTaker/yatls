import hashlib
import hmac


def p_hash(secret, seed, length):
    out = b""
    ai = seed

    while len(out) < length:
        ai = hmac.HMAC(secret, ai, hashlib.sha256).digest()
        digest = hmac.HMAC(secret, ai + seed, hashlib.sha256).digest()
        out += digest

    return out[:length]


def tls_prf(secret, label, seed, length):
    return p_hash(secret, label + seed, length)
