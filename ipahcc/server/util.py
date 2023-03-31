#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2023  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
from cryptography.x509.oid import NameOID

from ipalib import x509

from ipahcc import hccplatform


def parse_rhsm_cert(data):
    """Parse RHSM certificate

    returns org_id and rhsm_id (CN UUID)
    """
    if isinstance(data, hccplatform.text):
        data = data.encode("ascii")

    cert = x509.load_pem_x509_certificate(data)

    nas = list(cert.subject)
    if len(nas) != 2 or nas[0].oid != NameOID.ORGANIZATION_NAME:
        raise ValueError(
            "Invalid cert subject {subject}.".format(subject=cert.subject)
        )
    try:
        org_id = int(nas[0].value, 10)
    except (ValueError, TypeError):
        raise ValueError(
            "Invalid cert subject {subject}.".format(subject=cert.subject)
        )
    return org_id, nas[1].value
