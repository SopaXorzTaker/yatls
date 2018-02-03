import struct
from yatls.fields.field import Field


class StructField(Field):
    """
    A field representing a raw C structure.
    """

    def __init__(self, name="", structure=""):
        """
        Initializes this StructField object.

        :param name: an optional name of this field
        :param structure: the raw structure string to use when encoding and decoding the field
        """
        super().__init__(name)

        if structure is None:
            raise TypeError("StructField requires a structure parameter")

        self.structure = structure

    def encode(self, value):
        return struct.pack(self.structure, value)

    def decode(self, buffer, offset=0):
        return struct.calcsize(self.structure), struct.unpack_from(buffer, offset)[0]
