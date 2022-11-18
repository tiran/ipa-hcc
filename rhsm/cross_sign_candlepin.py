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
- key usage (cert & CRL signing)
- EKU (CA with pathlen=0)
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
from cryptography.x509.oid import NameOID

ROOT_CA_FILE = "hmsidm-root-ca.pem"
HMSIDM_CANDLEPIN_CA_FILE = "hmsidm-candlepin-ca.pem"
ORIG_CANDLEPIN_CA_FILE = "candlepin-redhat-ca.pem"
BUNDLE_FILE = "hmsidm-ca-bundle.pem"

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


def create_root_ca(
    subject: x509.Name,
    not_valid_after: datetime.datetime,
    key_size: int = KEY_SIZE,
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
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
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
    days: int = 730,
    key_size: int = KEY_SIZE,
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
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
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


def main():
    with open(ORIG_CANDLEPIN_CA_FILE, "rb") as f:
        template_cert = x509.load_pem_x509_certificate(f.read())

    root_ca_cert, root_ca_key = create_root_ca(
        ROOT_CA_SUBJECT, not_valid_after=template_cert.not_valid_after
    )
    hmsidm_candlepin_ca = create_cross_ca(
        template_cert, root_ca_cert, root_ca_key
    )
    del root_ca_key

    root_pem = root_ca_cert.public_bytes(serialization.Encoding.PEM)
    hmsidm_candlepin_pem = hmsidm_candlepin_ca.public_bytes(
        serialization.Encoding.PEM
    )

    with open(ROOT_CA_FILE, "wb") as f:
        f.write(root_pem)
    with open(HMSIDM_CANDLEPIN_CA_FILE, "wb") as f:
        f.write(hmsidm_candlepin_pem)
    with open(BUNDLE_FILE, "wb") as f:
        f.write(hmsidm_candlepin_pem)
        f.write(root_pem)


if __name__ == "__main__":
    main()
