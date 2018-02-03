from yatls.fields import Field, IntField


class OpaqueField(Field):
    """
    A byte array field, prefixed by its length in bytes.
    """

    def __init__(self, name="", floor=0, ceiling=None):
        """
        Initializes this OpaqueField object.

        :param name: an optional name of this field
        :param floor: the minimum length of this field (optional)
        :param ceiling: the maximum length of this field
        """

        super().__init__(name)

        if ceiling is None:
            raise TypeError("OpaqueField requires a ceiling parameter")

        self.floor = floor
        self.ceiling = ceiling

        # Find a minimum suitable length for the length field
        length_field_size = 1

        while self.ceiling >= 2 ** (length_field_size * 8):
            length_field_size += 1

        self.length_field_size = length_field_size

    def encode(self, value):
        """
        Encodes this field (into bytes)
        :param value: the bytes to encode
        :return: the encoded data
        """

        if len(value) < self.floor or len(value) > self.ceiling:
            raise ValueError("Invalid length")

        out = b""
        out += IntField(length=self.length_field_size).encode(len(value))

        for value in value:
            out += bytes([value])

        return out

    def decode(self, buffer, offset=0):
        """
        Decodes this field (from bytes)
        :param buffer: the buffer to decode this field from
        :param offset: the offset to read this buffer from
        :return: the decoded bytes
        """

        out = b""
        initial_offset = offset

        size, length = IntField(length=self.length_field_size).decode(buffer, offset)
        offset += size

        for _ in range(length):
            value = buffer[offset]
            offset += 1

            out += bytes([value])

        return offset - initial_offset, out
