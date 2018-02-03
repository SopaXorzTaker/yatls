from yatls.fields import Structure, IntField
from yatls.protocol.fields import OpaqueField, EnumField
from yatls.protocol.messages.handshake.certificate_request import CertificateRequest
from yatls.protocol.messages.handshake.client_key_exchange import ClientKeyExchange
from yatls.protocol.messages.handshake.finished import Finished
from yatls.protocol.messages.handshake.hello_request import HelloRequest
from yatls.protocol.messages.handshake.server_hello_done import ServerHelloDone
from yatls.protocol.messages.handshake.server_key_exchange import ServerKeyExchange
from .certificate import *
from .client_hello import *
from .server_hello import *


class HandshakeType(EnumField):
    ENUM_MEMBERS = {
        0: "hello_request",
        1: "client_hello",
        2: "server_hello",
        11: "certificate",
        12: "server_key_exchange",
        13: "certificate_request",
        14: "server_hello_done",
        15: "certificate_verify",
        16: "client_key_exchange",
        20: "finished",
        255: None
    }


class Handshake(Structure):
    HANDSHAKE_MESSAGES = {
        "hello_request": HelloRequest,
        "client_hello": ClientHello,
        "server_hello": ServerHello,
        "certificate": Certificate,
        "server_key_exchange": ServerKeyExchange,
        "certificate_request": CertificateRequest,
        "server_hello_done": ServerHelloDone,
        # "certificate_verify": None,
        "client_key_exchange": ClientKeyExchange,
        "finished": Finished
    }

    STRUCTURE_FIELDS = [
        HandshakeType(name="handshake_type"),
        OpaqueField(name="body", ceiling=2**24-1)
    ]

    def decode_auto(self, buffer, offset=0):
        size, values = self.decode(buffer, offset)

        if values["handshake_type"] in self.HANDSHAKE_MESSAGES:
            return size, (values["handshake_type"],
                          self.HANDSHAKE_MESSAGES[values["handshake_type"]]().decode(values["body"])[1])
        else:
            raise ValueError("Unknown handshake message type")
