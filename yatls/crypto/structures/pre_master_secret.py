from yatls.fields import Structure, ByteArrayField
from yatls.protocol.fields import OpaqueField
from yatls.protocol.structures import ProtocolVersion


class PreMasterSecret(Structure):
    STRUCTURE_FIELDS = [
        ProtocolVersion(name="client_version"),
        ByteArrayField(name="random", length=46)
    ]


class EncryptedPreMasterSecret(Structure):
    STRUCTURE_FIELDS = [
        OpaqueField(name="encrypted", ceiling=2**16-1)
    ]
