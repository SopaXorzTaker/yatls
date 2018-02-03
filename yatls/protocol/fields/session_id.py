from yatls.fields import Field, IntField


class SessionID(Field):
    def encode(self, value):
        if len(value) > 32:
            raise ValueError("Invalid session ID length")

        return IntField(length=1).encode(len(value)) + value

    def decode(self, buffer, offset=0):
        length = buffer[offset]
        offset += 1

        if length > 32:
            raise ValueError("Invalid session ID length")

        data = buffer[offset: offset + length]
        return length + 1, data
