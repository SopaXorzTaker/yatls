from yatls.fields import Structure, IntField
from yatls.protocol.fields import OpaqueField


class Extension(Structure):
    STRUCTURE_FIELDS = [
        IntField(name="extension_type", length=2),
        OpaqueField(name="extension_data", ceiling=2**16-1)
    ]
