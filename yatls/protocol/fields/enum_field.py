from yatls.fields import Field, IntField


class EnumField(Field):
    """
    A field representing an enum (as int of minimal possible length)
    """

    ENUM_MEMBERS = {}

    def __init__(self, name=""):
        super().__init__(name)

        member_size = 1
        while max(self.ENUM_MEMBERS) >= 2 ** (member_size * 8):
            member_size += 1

        self.member_size = member_size

    def encode(self, value):
        """
        Encodes an enum item.
        :param value: the value to encode
        :return: the encoded item as an integer of appropriate size
        """

        for member, member_value in self.ENUM_MEMBERS.items():
            if member_value == value:
                break
        else:
            raise KeyError("No such value in enum")

        return IntField(length=self.member_size).encode(member)

    def decode(self, buffer, offset):
        """
        Decodes an enum item.
        :param buffer: the buffer to decode from
        :param offset: the offset to read the buffer from
        :return: the corresponding enum member
        """
        return self.member_size, self.ENUM_MEMBERS[IntField(length=self.member_size).decode(buffer, offset)[1]]
