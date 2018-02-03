from yatls.crypto.structures.pre_master_secret import EncryptedPreMasterSecret
from yatls.fields import Structure


class ClientKeyExchange(Structure):
    STRUCTURE_FIELDS = [
        EncryptedPreMasterSecret(name="exchange_keys")
    ]
