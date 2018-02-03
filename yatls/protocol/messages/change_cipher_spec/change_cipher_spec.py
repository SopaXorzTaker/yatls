from yatls.fields import Structure
from yatls.protocol.fields import EnumField


class ChangeCipherSpecType(EnumField):
    ENUM_MEMBERS = {
        1: "change_cipher_spec",
        255: None
    }


class ChangeCipherSpec(Structure):
    STRUCTURE_FIELDS = [
        ChangeCipherSpecType(name="type")
    ]
