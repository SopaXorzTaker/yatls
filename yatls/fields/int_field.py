from yatls.fields.field import Field


class IntField(Field):
    """
    A field representing a raw, network-order integer.
    """

    def __init__(self, name="", length=None):
        """
        Initializes this IntField object.

        :param name: an optional name of this field
        :param length: the size of this integer field in bytes
        """

        super().__init__(name)

        if length is None:
            raise TypeError("IntField requires a length parameter")

        self.length = length

    def encode(self, value):
        return int.to_bytes(value, self.length, "big")

    def decode(self, buffer, offset=0):
        return self.length, int.from_bytes(buffer[offset: offset + self.length], "big")