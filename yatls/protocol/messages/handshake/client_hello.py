from yatls.fields import Structure, ByteArrayField
from yatls.protocol.fields import SessionID, ListField
from yatls.protocol.structures import ProtocolVersion, Random
from yatls.protocol.structures.extension import Extension
from yatls.protocol.messages.handshake.compression_methods import CompressionMethod


class ClientHello(Structure):
    STRUCTURE_FIELDS = [
        ProtocolVersion(name="client_version"),
        Random(name="random"),
        SessionID(name="session_id"),
        ListField(name="cipher_suites", element=ByteArrayField(length=2), ceiling=2**16-2),
        ListField(name="compression_methods", element=CompressionMethod(), ceiling=2**8-1),
        ListField(name="extensions", element=Extension(), ceiling=2**16-1, ignore_empty=True)
    ]
