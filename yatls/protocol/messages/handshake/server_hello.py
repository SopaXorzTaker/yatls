from yatls.fields import Structure, IntField, ByteArrayField
from yatls.protocol.fields import SessionID, ListField
from yatls.protocol.structures import ProtocolVersion, Random
from yatls.protocol.structures.extension import Extension
from yatls.protocol.messages.handshake.compression_methods import CompressionMethod


class ServerHello(Structure):
    STRUCTURE_FIELDS = [
        ProtocolVersion(name="client_version"),
        Random(name="random"),
        SessionID(name="session_id"),
        ByteArrayField(name="cipher_suite", length=2),
        CompressionMethod(name="compression_method"),
        ListField(name="extensions", element=Extension(), ceiling=2**16-1, ignore_empty=True)
    ]
