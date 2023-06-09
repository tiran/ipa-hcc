#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2023  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
import os
import typing

from cryptography.x509.oid import NameOID
from ipalib import x509


def parse_rhsm_cert(
    data: typing.Union[str, typing.ByteString]
) -> typing.Tuple[int, str]:
    """Parse RHSM certificate

    returns org_id and rhsm_id (CN UUID)
    """
    if isinstance(data, str):
        data = data.encode("ascii")

    cert = x509.load_pem_x509_certificate(data)

    nas = list(cert.subject)
    if len(nas) != 2 or nas[0].oid != NameOID.ORGANIZATION_NAME:
        raise ValueError(f"Invalid cert subject {cert.subject}.")
    try:
        org_id = int(nas[0].value, 10)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid cert subject {cert.subject}.") from None
    return org_id, nas[1].value


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
            data = input(prompt)
        except (KeyboardInterrupt, EOFError):
            return False
        else:
            if data in ("y", "yes"):
                return True
            elif data in ("n", "no"):
                return False
            elif default is not None and not data:
                return default
