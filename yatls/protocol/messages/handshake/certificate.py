from yatls.fields import Structure
from yatls.protocol.fields import ListField, OpaqueField


class Certificate(Structure):
    STRUCTURE_FIELDS = [
        ListField(name="certificate_list", ceiling=2**24-1, element=OpaqueField(ceiling=2**24-1))
    ]