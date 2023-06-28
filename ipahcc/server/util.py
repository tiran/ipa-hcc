#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2023  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
import os
import typing
from datetime import datetime, timezone

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from ipalib import x509

RFC4514_MAP = {
    NameOID.EMAIL_ADDRESS: "E",
}


def rfc3339_datetime(dt: datetime) -> str:
    """Convert datetime to RFC 3339 compatible string"""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat("T", timespec="seconds")


def create_certinfo(
    cert: x509.IPACertificate, nickname: typing.Optional[str] = None
) -> dict:
    """Create certinfo dict from a cert and optional nickname"""
    certinfo = {
        "nickname": nickname,
        # cryptography 3.2.1 on RHEL 8 does not support RFC map
        "issuer": cert.issuer.rfc4514_string(),
        "subject": cert.subject.rfc4514_string(),
        "pem": cert.public_bytes(Encoding.PEM).decode("ascii"),
        # JSON number type cannot handle large serial numbers
        "serial_number": str(cert.serial_number),
        "not_before": rfc3339_datetime(cert.not_valid_before),
        "not_after": rfc3339_datetime(cert.not_valid_after),
    }
    if nickname is None:
        certinfo["nickname"] = certinfo["subject"]
    return certinfo


def parse_rhsm_cert(
    data: typing.Union[str, typing.ByteString]
) -> typing.Tuple[str, str]:
    """Parse RHSM certificate

    returns org_id and rhsm_id (CN UUID)
    """
    if isinstance(data, str):
        data = data.encode("ascii")

    cert = x509.load_pem_x509_certificate(data)

    nas = list(cert.subject)
    if len(nas) != 2 or nas[0].oid != NameOID.ORGANIZATION_NAME:
        raise ValueError(f"Invalid cert subject {cert.subject}.")
    return nas[0].value, nas[1].value


def read_cert_dir(path: str) -> str:
    """Read certs from DIR and return a PEM bundle"""
    data = []
    for filename in os.listdir(path):
        if not filename.endswith(".pem"):
            continue
        absname = os.path.join(path, filename)
        with open(absname, encoding="utf-8") as f:
            data.append(f.read())
    # trust anchor last
    data.sort(reverse=True)
    return "\n".join(data)


def prompt_yesno(label, default: typing.Optional[bool] = None) -> bool:
    """
    Prompt user for yes/no input. This method returns True/False according
    to user response.

    Parameter "default" should be True, False or None

    If Default parameter is not None, user can enter an empty input instead
    of Yes/No answer. Value passed to Default is returned in that case.

    If Default parameter is None, user is asked for Yes/No answer until
    a correct answer is provided. Answer is then returned.

    `KeyboardInterrupt` or `EOFError` is interpreted as "no".
    """

    default_prompt = None  # type: typing.Optional[str]
    if default is not None:
        if default:
            default_prompt = "Yes"
        else:
            default_prompt = "No"

    if default_prompt:
        prompt = "%s Yes/No (default %s): " % (label, default_prompt)
    else:
        prompt = "%s Yes/No: " % label

    while True:
        try:
            data = input(prompt).lower()
        except (KeyboardInterrupt, EOFError):
            return False
        else:
            if data in ("y", "yes"):
                return True
            elif data in ("n", "no"):
                return False
            elif default is not None and not data:
                return default
