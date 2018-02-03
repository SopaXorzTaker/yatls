from yatls.crypto.x509 import asn1, oid


def x509_subject_parse(subject):
    # Parse an X.509 subject (OID + strings)
    out = []

    for pair in subject:
        field_oid, value = pair[0]
        out.append([oid.oid_lookup(field_oid), value])

    return out


def x509_cert_parse(data):
    # Parse an X.509 certificate
    certificate = asn1.asn1_decode(data)[1]
    basic_certificate = []

    version = 0
    issuer_unique_id = None
    subject_unique_id = None
    extensions = []

    # Optional values
    for field in certificate[0]:
        if isinstance(field, tuple):
            if field[0] == 0:
                version = field[1]
            elif field[0] == 1:
                issuer_unique_id = field[1]
            elif field[0] == 2:
                subject_unique_id = field[1]
            elif field[0] == 3:
                extensions = field[1]
        else:
            basic_certificate.append(field)

    serial = basic_certificate[0]
    tbs_signature_algorithm = basic_certificate[1]
    issuer = basic_certificate[2]
    validity = basic_certificate[3]
    subject = basic_certificate[4]
    subject_key_info = basic_certificate[5]

    raw_sequence = asn1.asn1_decode_raw(data)[1][3]
    tbs_size = asn1.asn1_decode_raw(raw_sequence)[0]
    raw_tbs_certificate = raw_sequence[:tbs_size]

    signature_algorithm = certificate[1]
    signature = certificate[2]

    if not tbs_signature_algorithm == signature_algorithm:
        raise ValueError("TBSCertificate signature algorithm mismatch")

    return {
        "version": version,
        "serial": serial,
        "signature_algorithm": tbs_signature_algorithm,
        "issuer": x509_subject_parse(issuer),
        "validity": validity,
        "subject": x509_subject_parse(subject),
        "subject_key_info": subject_key_info,
        "issuer_unique_id": issuer_unique_id,
        "subject_unique_id": subject_unique_id,
        "extensions": extensions,
        "raw_tbs_certificate": raw_tbs_certificate,
        "signature": signature
    }


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as in_file:
        data = in_file.read()

        values = x509_cert_parse(data)
        print("Issuer: ", values["issuer"])
        print("Subject: ", values["subject"])

        signature_algorithm = values["signature_algorithm"][0]
        subject_key_algorithm = values["subject_key_info"][0][0]

        print("Signature algorithm: ", oid.oid_lookup(signature_algorithm))
        print("Subject key algorithm: ", oid.oid_lookup(subject_key_algorithm))

        print("Raw subject key: ", values["subject_key_info"])
        print("Raw signature: ", values["signature"])

        if values["issuer"] == values["subject"]:
            print("(self-signed)")
