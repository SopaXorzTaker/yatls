from yatls.fields.field import Field


class Structure(Field):
    """
    A structure (which can contain multiple fields inside).
    """

    STRUCTURE_FIELDS = []

    def __init__(self, name=""):
        """
        Initializes this Structure object.
        :param name: an optional name of this field
        """

        super().__init__(name)

    def encode(self, values):
        """
        Encodes this structure (into bytes).
        :param values: a dictionary of field names and corresponding values
        :return: the encoded structure
        """

        out = b""

        for field in self.STRUCTURE_FIELDS:
            out += field.encode(values[field.name])

        return out

    def decode(self, buffer, offset=0):
        """
        Decodes this structure from a given buffer into a dictionary corresponding to the field names and their values.
        :param buffer: the buffer to decode this structure from
        :param offset: the offset to read the buffer from
        :return: the decoded structure
        """

        values = {}
        initial_offset = offset

        for field in self.STRUCTURE_FIELDS:
            length, value = field.decode(buffer, offset)
            offset += length

            values[field.name] = value

        return offset - initial_offset, values
