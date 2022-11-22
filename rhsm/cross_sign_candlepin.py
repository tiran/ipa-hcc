#!/usr/bin/env python3
"""Cross-sign 'Red Hat Candlepin Authority'

The original 'Red Hat Candlepin Authority' CA certificate has a SHA-1
signature (sha1WithRSAEncryption). This script generates a new root CA
certificate and a cross-signs Candlepin CA. The cross-signed CA has all
necessary properties to verify a RHSM host certificate.

The private key of the root CA is ephemeral and not serialized to disk.

Copied properties:

- subject
- public key
- not valid after
- SKID (subject key identifier)

New / changed properties:

- issuer (new root CA)
- serial number (random)
- not valid before (set to NOW)
- AKID (authority key identifier, set to SKID of new root CA)
- key usage (cert signing)
- basic constraint (CA with pathlen=0)
- extended key usage (limited to TLS client auth)
- certificate policy
- signature (sha256WithRSAEncryption)

Example::

    $ openssl verify -show_chain -CAfile hmsidm-ca-bundle.pem cert.pem 
    cert.pem: OK
    Chain:
    depth=0: O = 7648012, CN = b4ab7ef2-973e-4423-ab55-5ed620050b4e (untrusted)
    depth=1: C = US, ST = North Carolina, O = "Red Hat, Inc.", OU = Red Hat Network, CN = Red Hat Candlepin Authority, emailAddress = ca-support@redhat.com
    depth=2: CN = US, ST = North Carolina, L = Raleigh, O = "Red Hat, Inc.", OU = HMSIDM, CN = HMSIDM Root CA

"""
import datetime
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

ROOT_CA_FILE = "hmsidm-root-ca.pem"
HMSIDM_CANDLEPIN_CA_FILE = "hmsidm-candlepin-ca.pem"
HMSIDM_CANDLEPIN_R2_CA_FILE = "hmsidm-candlepin-r2-ca.pem"
BUNDLE_FILE = "hmsidm-ca-bundle.pem"

OID_MAP = {
    x509.ObjectIdentifier("1.2.840.113549.1.9.1"): "E",
}

NOW = datetime.datetime.utcnow()
KEY_SIZE = 4096

ROOT_CA_SUBJECT = x509.Name(
    [
        x509.NameAttribute(NameOID.COMMON_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "North Carolina"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Raleigh"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Red Hat, Inc."),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "HMSIDM"),
        x509.NameAttribute(NameOID.COMMON_NAME, "HMSIDM Root CA"),
    ]
)

HMSIDM_POLICY_OID = x509.ObjectIdentifier("2.16.840.1.113730.3.8.100.3.1")
HMSIDM_POLICY = x509.CertificatePolicies(
    [
        x509.PolicyInformation(
            HMSIDM_POLICY_OID,
            [
                "Cross-signed Candlepin CA for HMS-IDM",
                "For use with Red Hat Console integration with IdM",
            ],
        )
    ]
)

# Red Hat Candlepin Authority
ORIG_CANDLEPIN_CA = b"""\
-----BEGIN CERTIFICATE-----
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
g6EHdPrR+A==
-----END CERTIFICATE-----
"""

# Red Hat Candlepin Authority R2
ORIG_CANDLEPIN_R2_CA = b"""\
-----BEGIN CERTIFICATE-----
MIIG9zCCBN+gAwIBAgICAs8wDQYJKoZIhvcNAQELBQAwgbExCzAJBgNVBAYTAlVT
MRcwFQYDVQQIDA5Ob3J0aCBDYXJvbGluYTEWMBQGA1UECgwNUmVkIEhhdCwgSW5j
LjEYMBYGA1UECwwPUmVkIEhhdCBOZXR3b3JrMTEwLwYDVQQDDChSZWQgSGF0IEVu
dGl0bGVtZW50IE9wZXJhdGlvbnMgQXV0aG9yaXR5MSQwIgYJKoZIhvcNAQkBFhVj
YS1zdXBwb3J0QHJlZGhhdC5jb20wHhcNMjExMTEyMTkyMDM4WhcNMzAxMDIxMTky
MDM4WjCBpzELMAkGA1UEBhMCVVMxFzAVBgNVBAgMDk5vcnRoIENhcm9saW5hMRYw
FAYDVQQKDA1SZWQgSGF0LCBJbmMuMRgwFgYDVQQLDA9SZWQgSGF0IE5ldHdvcmsx
JzAlBgNVBAMMHlJlZCBIYXQgQ2FuZGxlcGluIEF1dGhvcml0eSBSMjEkMCIGCSqG
SIb3DQEJARYVY2Etc3VwcG9ydEByZWRoYXQuY29tMIICIjANBgkqhkiG9w0BAQEF
AAOCAg8AMIICCgKCAgEAkeaC9aGPtWyOZ4yfvaWe7Pp4M9fgURilejp5iXiZOh82
36iKQlkLluW32HRmi5ev8Qh7oyA2i1YQ3DOgaWEC0qid6ZrhBPBU8Z89L1kLQmfF
4ogpOGXeS2NlRjlsTRzalnjgFbdTZDZaOvepdM2FNdZQYPXZ4v8JyLUU4tmCd8Py
x6VEOkcaVPilj22PfzQ01mV5UbnjXEpPZbRHwbo4MJn/Oj+MzJgpnMXsGceb4IHk
yp1DEtZkcGjr1F+q7teghm5aC17c+rGZUrdsJfiyMooodmocP5THeN6jpHQ1lvhX
1Cvl0MIBzy5mBHHOjvvY4wlFQE0f4d/TJ1MGYfC9UZMVzJ6VExuI/DgnxUQ2LN1U
wUYh2UskXXHk07T2QYknmlzCXclO3mqqt7KJw2DIiw3Iz6FEs68SXEWG+tuEiOTR
KkrGPUyA3wUm7bgdwiHiDwGvpwlAd7Hufuuq5DLoD66kMoFAfIKv7qmPZkoLudFG
txtKW65bVzPWNri9nsVdtfAcVs1jXobsUmVGQKAEiGyHH81ffdg04xiMnbyVHh5j
ryBEoQvhGatQp8gD0FzNaqhOKXCD/Qa9SqcMNet2D5knz0dSvw/nLAaGjQVl/pp/
phdgJe9vY2ZkF+XT9XzWV8oX+hp4v7cgmvtw6r3xf89PPRd5mDtIOkt+InfTX7MC
AwEAAaOCAR8wggEbMB0GA1UdDgQWBBQQCKHAleYBMrONUiUb2NtK5GFi6jCB5QYD
VR0jBIHdMIHagBTESXhWRZ0eLGFgw2ZLWAU3LwMie6GBtqSBszCBsDELMAkGA1UE
BhMCVVMxFzAVBgNVBAgMDk5vcnRoIENhcm9saW5hMRAwDgYDVQQHDAdSYWxlaWdo
MRYwFAYDVQQKDA1SZWQgSGF0LCBJbmMuMRgwFgYDVQQLDA9SZWQgSGF0IE5ldHdv
cmsxHjAcBgNVBAMMFUVudGl0bGVtZW50IE1hc3RlciBDQTEkMCIGCSqGSIb3DQEJ
ARYVY2Etc3VwcG9ydEByZWRoYXQuY29tggkAkYrPyoUAAAAwEgYDVR0TAQH/BAgw
BgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAgEAZ4JS9omsVkt66lrC8M6Tkd6wrhr+
rYulUkwEcF/B9sB2/gYbKhJdQBpIDbUtBE8DEF380OP+w5QxGv/+dFNVq1Qhcje9
Qb3lRedRPfpC2afNJsr8Ev+zdMJFExCfRyKlhDgbe6Dd8WoVKnD4F7IJqt8HTuVE
ExsrfgyGdkk67RtcMs8T9GimDxd0xiUXsbVkE6ATeSK9ELha01jUkGT/y9WDrTpr
U01dTsrDLws9KmWbxWrU4OHswRe2NznbGRKgTs83efUkolAYlMCuT8jx6P5kNLWm
NE383TrUtFrllA5/JO8QviWrmvVLR+rOBjE1PHswhsvsKRaxHkcB7XLHDexYcIAs
hvoe7YAgqmFEcroLvpmeUtg5fOMlVb4ORIsMf16vqmXNrSGywJLw3tUUEYWuEChh
WshcbRf5EE1ROao8zGYnLhVF4OIH4ZMy3dFEpbXaLdLleWnOX6BJEvYL/71Xsb1l
WCSgufrk+or9Lz+SMJmJBzHqMqdGIFMINHL+Ritv63uhPMTklZec7ePEbtU1pbtI
NK74t9l/7gIGz05fLRJGDAVEmC6LFRpyyZSh6qELwwNVot1y0xojPSy3dbLmUxuO
DwBHkHsxstyyg2py9rPYj3Ik8rXpRp5yRW1+ehFI8PenMOA7RWT+u/xor6XrpiP9
3N4ml0cLV0ASeWU=
-----END CERTIFICATE-----
"""


def create_root_ca(
    subject: x509.Name,
    not_valid_after: datetime.datetime,
    key_size: int,
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    pub_key = key.public_key()

    builder = x509.CertificateBuilder()
    builder = builder.public_key(pub_key)
    builder = builder.serial_number(x509.random_serial_number())

    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)

    builder = builder.not_valid_before(NOW)
    builder = builder.not_valid_after(not_valid_after)

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    # CA is limited to client cert authentiation
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=True,
    )

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(pub_key),
        critical=False,
    )

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(pub_key),
        critical=False,
    )

    builder = builder.add_extension(
        HMSIDM_POLICY,
        critical=False,
    )

    cert = builder.sign(key, hashes.SHA256())
    return cert, key


def create_cross_ca(
    template_cert: x509.Certificate,
    issuer: x509.Certificate,
    issuer_key: rsa.RSAPrivateKey,
    path_length: int = 0,
) -> x509.Certificate:
    builder = x509.CertificateBuilder()
    builder = builder.public_key(template_cert.public_key())
    builder = builder.serial_number(x509.random_serial_number())

    builder = builder.subject_name(template_cert.subject)
    builder = builder.issuer_name(issuer.subject)

    builder = builder.not_valid_before(NOW)
    builder = builder.not_valid_after(template_cert.not_valid_after)

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    # CA is limited to client cert authentiation
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=True,
    )

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=path_length),
        critical=True,
    )

    skid_ext = template_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    )
    builder = builder.add_extension(
        skid_ext.value,
        critical=False,
    )

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer.public_key()
        ),
        critical=False,
    )

    builder = builder.add_extension(
        HMSIDM_POLICY,
        critical=False,
    )

    cert = builder.sign(issuer_key, hashes.SHA256())
    return cert


def encode_name(name: x509.Name) -> bytes:
    return name.rfc4514_string(OID_MAP).encode("utf-8")


def main():
    orig_candlepin = x509.load_pem_x509_certificate(ORIG_CANDLEPIN_CA)
    orig_candlepin_r2 = x509.load_pem_x509_certificate(ORIG_CANDLEPIN_R2_CA)

    root_ca_cert, root_ca_key = create_root_ca(
        subject=ROOT_CA_SUBJECT,
        not_valid_after=min(
            orig_candlepin.not_valid_after, orig_candlepin_r2.not_valid_after
        ),
        key_size=KEY_SIZE,
    )
    hmsidm_candlepin = create_cross_ca(
        template_cert=orig_candlepin,
        issuer=root_ca_cert,
        issuer_key=root_ca_key,
    )
    hmsidm_candlepin_r2 = create_cross_ca(
        template_cert=orig_candlepin_r2,
        issuer=root_ca_cert,
        issuer_key=root_ca_key,
    )
    del root_ca_key

    root_pem = root_ca_cert.public_bytes(serialization.Encoding.PEM)
    hmsidm_candlepin_pem = hmsidm_candlepin.public_bytes(
        serialization.Encoding.PEM
    )
    hmsidm_candlepin_r2_pem = hmsidm_candlepin_r2.public_bytes(
        serialization.Encoding.PEM
    )

    with open(ROOT_CA_FILE, "wb") as f:
        f.write(root_pem)
    with open(HMSIDM_CANDLEPIN_CA_FILE, "wb") as f:
        f.write(hmsidm_candlepin_pem)
    with open(HMSIDM_CANDLEPIN_R2_CA_FILE, "wb") as f:
        f.write(hmsidm_candlepin_r2_pem)
    with open(BUNDLE_FILE, "wb") as f:
        f.write(encode_name(hmsidm_candlepin.subject) + b"\n")
        f.write(hmsidm_candlepin_pem)
        f.write(b"\n" + encode_name(hmsidm_candlepin_r2.subject) + b"\n")
        f.write(hmsidm_candlepin_r2_pem)
        f.write(b"\n" + encode_name(root_ca_cert.subject) + b"\n")
        f.write(root_pem)


if __name__ == "__main__":
    main()
