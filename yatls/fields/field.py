class Field(object):
    """
    A protocol field that can be encoded and decoded.
    """

    name = ""

    def __init__(self, name=""):
        """
        Initializes this Field object.

        :param name: an optional name of this field
        """

        self.name = name

    def encode(self, value):
        """
        Encodes this field with a given value.
        :param value: the value to encode the field with
        :return: the encoded value
        """

        return None

    def decode(self, buffer, offset):
        """
        Decodes this field from a buffer, starting at offset and returns the amount of bytes read and the value.
        :param buffer: the buffer the read the field from
        :param offset: the offset to read the buffer from
        :return: a tuple (bytes read, field value)
        """

        return None