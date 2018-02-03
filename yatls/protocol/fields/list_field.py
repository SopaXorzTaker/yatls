from yatls.fields import Field, IntField


class ListField(Field):
    """
    A list field, prefixed by its length in bytes.
    """

    def __init__(self, name="", floor=0, ceiling=None, element=None, ignore_empty=False):
        """
        Initializes this ListField object.

        :param name: an optional name of this field
        :param floor: the minimum length of this field (optional)
        :param ceiling: the maximum length of this field
        :param element: the element field (which this ListField is composed of)
        :param ignore_empty: don't decode this field if there's no data to decode it from
        """

        super().__init__(name)

        if ceiling is None:
            raise TypeError("ListField requires a ceiling parameter")

        if element is None:
            raise TypeError("ListField requires an element parameter")

        self.floor = floor
        self.ceiling = ceiling
        self.element = element

        # Find a minimum suitable length for the length field
        length_field_size = 1

        while self.ceiling >= 2 ** (length_field_size * 8):
            length_field_size += 1

        self.length_field_size = length_field_size
        self.ignore_empty = ignore_empty

    def encode(self, values):
        """
        Encodes this field (into bytes)
        :param values: the values to encode
        :return: the encoded values
        """

        out = b""

        for value in values:
            out += self.element.encode(value)

        if len(out) < self.floor or len(out) > self.ceiling:
            raise ValueError("Invalid length")

        out = IntField(length=self.length_field_size).encode(len(out)) + out

        return out

    def decode(self, buffer, offset=0):
        """
        Decodes this field (from bytes)
        :param buffer: the buffer to decode this field from
        :param offset: the offset to read this buffer from
        :return: the decoded values
        """

        values = []
        initial_offset = offset

        if self.ignore_empty and not len(buffer[offset:]):
            return 0, []

        size, length = IntField(length=self.length_field_size).decode(buffer, offset)
        offset += size

        data_offset = offset

        while offset - data_offset < length:
            size, value = self.element.decode(buffer, offset)
            offset += size

            values.append(value)

        return offset - initial_offset, values
