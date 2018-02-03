from yatls.fields import Structure
from yatls.protocol.fields import EnumField


class HashAlgorithm(EnumField):
    ENUM_MEMBERS = {
        0: "none",
        1: "md5",
        2: "sha1",
        3: "sha224",
        4: "sha256",
        5: "sha384",
        6: "sha512",
        255: None
    }


class SignatureAlgorithm(EnumField):
    ENUM_MEMBERS = {
        0: "anonymous",
        1: "rsa",
        2: "dsa",
        3: "ecdsa",
        255: None
    }


class SignatureAndHashAlgorithm(Structure):
    STRUCTURE_FIELDS = [
        HashAlgorithm(name="hash"),
        SignatureAlgorithm(name="signature")
    ]
