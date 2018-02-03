from yatls.fields import Structure
from yatls.protocol.fields import OpaqueField
from yatls.protocol.messages.handshake.signature_and_hash_algorithm import SignatureAndHashAlgorithm


class DigitallySigned(Structure):
    STRUCTURE_FIELDS = [
        SignatureAndHashAlgorithm(name="algorithm"),
        OpaqueField(name="signature", ceiling=2**16-1)
    ]
