from yatls.protocol.fields import EnumField


class ContentType(EnumField):
    ENUM_MEMBERS = {
        20: "change_cipher_spec",
        21: "alert",
        22: "handshake",
        23: "application_data",
        255: None
    }
