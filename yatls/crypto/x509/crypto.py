import hashlib

SIGNATURE_DIGEST_ALGORITHMS = {
    "1.2.840.113549.1.1.11": hashlib.sha256,
    "1.2.840.113549.1.1.12": hashlib.sha384
}


def digest(data, oid):
    return SIGNATURE_DIGEST_ALGORITHMS[oid](data).digest()
