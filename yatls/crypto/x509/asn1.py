ASN1_UNIVERSAL = {
    0: "RESERVED",
    1: "BOOLEAN",
    2: "INTEGER",
    3: "BIT STRING",
    4: "OCTET STRING",
    5: "NULL",
    6: "OBJECT IDENTIFIER",
    7: "ObjectDescriptor",
    8: "EXTERNAL",
    9: "REAL",
    10: "ENUMERATED",
    11: "EMBEDDED PDV",
    12: "UTF8String",
    13: "RELATIVE-OID",
    16: "SEQUENCE",
    17: "SET",
    18: "NumericString",
    19: "PrintableString",
    20: "TeletexString",
    21: "VideotexString",
    22: "IA5String",
    23: "UTCTime",
    24: "GeneralizedTime",
    25: "GraphicString",
    26: "VisibleString",
    27: "GeneralString",
    28: "UniversalString",
    29: "CharacterString",
    30: "BMPString"
}

ASN1_CLASS = {
    0: "universal",
    1: "application",
    2: "context-specific",
    3: "private"
}


def vlq_decode(buf, offset=0):
    val = 0
    initial_offset = offset

    while buf[offset] & 128:
        val <<= 7
        val |= buf[offset] & 127
        offset += 1

    val <<= 7
    val |= buf[offset]
    offset += 1

    return offset - initial_offset, val


def asn1_decode_raw(buf, offset=0):
    object_data = None
    initial_offset = offset

    flags = buf[offset]
    offset += 1

    object_class = ASN1_CLASS[(flags >> 6) & 3]
    object_structured = (flags >> 5) & 1
    object_tag_raw = flags & 31

    object_length_raw = buf[offset]
    offset += 1

    if object_tag_raw == 31:
        object_tag_size, object_tag_raw = vlq_decode(buf, offset)
        offset += object_tag_size

    if object_length_raw < 128:
        object_data = buf[offset: offset + object_length_raw]
        offset += object_length_raw

    elif object_length_raw == 128:
        object_data = bytearray()

        while not buf[offset: offset + 2] == "\x00\x00":
            object_data += buf[offset]
            offset += 1

        offset += 2

        object_data = bytes(object_data)
    elif object_length_raw > 128:
        object_length_size = object_length_raw - 128
        object_length = int.from_bytes(buf[offset: offset + object_length_size], "big")
        offset += object_length_size

        object_data = buf[offset: offset + object_length]
        offset += object_length

    size = offset - initial_offset

    return size, (object_class, object_structured, object_tag_raw, object_data)


def asn1_decode(buf, offset=0):
    size, (object_class, object_structured, object_tag_raw, object_data) = asn1_decode_raw(buf, offset)

    if object_class == "universal":
        object_tag = ASN1_UNIVERSAL[object_tag_raw]
        # print("{}: {}".format(offset, object_tag))

        if object_tag == "BOOLEAN":
            return size, bool(object_data[0])

        elif object_tag == "INTEGER":
            return size, int.from_bytes(object_data, "big")

        elif object_tag == "BIT STRING":
            bit_string = object_data

            if bit_string[0] == 0:
                bit_string = bit_string[1:]

            return size, bit_string

        elif object_tag == "OCTET STRING":
            return size, object_data

        elif object_tag == "NULL":
            return size, None

        elif object_tag == "OBJECT IDENTIFIER":
            first_digit = object_data[0] // 40
            second_digit = object_data[0] % 40
            vlq_digits = []

            vlq = object_data[1:]
            vlq_offset = 0

            while vlq_offset < len(vlq):
                vlq_size, current_digit = vlq_decode(vlq, vlq_offset)
                vlq_offset += vlq_size
                vlq_digits.append(current_digit)

            return size, ".".join([str(x) for x in [first_digit, second_digit] + vlq_digits])

        elif object_tag in ["SEQUENCE", "SET"]:
            items = []
            sequence_offset = 0

            while sequence_offset < len(object_data):
                item_size, item = asn1_decode(object_data, sequence_offset)
                sequence_offset += item_size
                items.append(item)

            return size, items

        elif object_tag in ["PrintableString", "UTF8String", "UTCTime"]:
            return size, object_data.decode("utf-8")

        else:
            raise ValueError("Unknown object tag {}".format(object_tag))

    elif object_class == "context-specific":
        # print("{}: Context {}".format(offset, object_tag_raw))

        return size, (object_tag_raw, asn1_decode(object_data)[1])

    else:
        raise ValueError("Unknown class {}".format(object_class))


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as input_file:
        data = input_file.read()
        print(asn1_decode(data))
