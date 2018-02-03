from yatls.protocol.fields import EnumField


class CompressionMethod(EnumField):
    ENUM_MEMBERS = {
        0: "null",
        255: None
    }
