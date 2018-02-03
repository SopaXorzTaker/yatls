from yatls.fields import *


class ProtocolVersion(Structure):
    STRUCTURE_FIELDS = [
        IntField(name="major", length=1),
        IntField(name="minor", length=1)
    ]
