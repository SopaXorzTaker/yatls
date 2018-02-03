KNOWN_OIDS = {
    "2.5.4.41": "name",
    "2.5.4.4":  "surname",
    "2.5.4.42": "givenName",
    "2.5.4.43": "initial",
    "2.5.4.44": "generationQualifier",

    "2.5.4.3":  "commonName",
    "2.5.4.7":  "localityName",
    "2.5.4.8":  "stateOrProvinceName",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName",
    "2.5.4.12": "title",
    "2.5.4.46": "dnQualifier",
    "2.5.4.6":  "countryName",
    "2.5.4.5":  "serialNumber",
    "2.5.4.65": "pseudonym",

    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",

    "1.2.840.10045.2.1":  "ecPublicKey",

    "1.2.840.10045.4.3.1": "ecdsaWithSHA224",
    "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
    "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
    "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
}


def oid_lookup(oid):
    if oid in KNOWN_OIDS:
        return KNOWN_OIDS[oid]

    return oid

