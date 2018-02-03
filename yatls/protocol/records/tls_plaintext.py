from yatls.fields import Structure, IntField
from yatls.protocol.fields import OpaqueField
from yatls.protocol.records.content_types import ContentType
from yatls.protocol.structures import ProtocolVersion


class TLSPlaintext(Structure):
    STRUCTURE_FIELDS = [
        ContentType(name="type"),
        ProtocolVersion(name="version"),
        OpaqueField(name="fragment", ceiling=2**14)
    ]
