from yatls.fields import *


class Random(Structure):
    STRUCTURE_FIELDS = [
        IntField(name="gmt_unix_time", length=4),
        ByteArrayField(name="random_bytes", length=28)
    ]
