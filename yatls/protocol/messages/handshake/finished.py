from yatls.fields import Structure, ByteArrayField


class Finished(Structure):
    STRUCTURE_FIELDS = [
        ByteArrayField(name="verify_data", length=12)
    ]
