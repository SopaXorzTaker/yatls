from yatls.fields import Structure
from yatls.protocol.fields import EnumField, ListField, OpaqueField
from yatls.protocol.messages.handshake.signature_and_hash_algorithm import SignatureAndHashAlgorithm


class ClientCertificateType(EnumField):
    ENUM_MEMBERS = {
        1: "rsa_sign",
        2: "dsa_sign",
        3: "rsa_fixed_dh",
        4: "dss_fixed_dh",
        5: "rsa_ephemeral_dh_RESERVED",
        6: "dss_ephemeral_dh_RESERVED",
        20: "fortezza_dms_RESERVED",
        255: None
    }


class CertificateRequest(Structure):
    STRUCTURE_FIELDS = [
        ListField(name="certificate_types", element=ClientCertificateType(), floor=1, ceiling=2**16-1),
        ListField(name="supported_signature_algorithms", element=SignatureAndHashAlgorithm(), ceiling=2**16-1),
        ListField(name="certificate_authorities", element=OpaqueField(floor=1, ceiling=2**16-1), ceiling=2**16-1)
    ]
