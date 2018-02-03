from yatls.fields.field import Field


class ByteArrayField(Field):
    """
    A field representing a byte array.
    """

    def __init__(self, name="", length=None):
        """
        Initializes this ByteArrayField object.

        :param name: an optional name of this field.
        :param length: length of this byte array
        """
        super().__init__(name)

        if length is None:
            raise TypeError("ByteArrayField requires a length parameter")

        self.length = length

    def encode(self, value):
        if not len(value) == self.length:
            raise ValueError("Invalid length")

        return value

    def decode(self, buffer, offset):
        read = buffer[offset: offset + self.length]

        if not len(read) == self.length:
            raise EOFError("Not enough data in the buffer")

        return self.length, read
