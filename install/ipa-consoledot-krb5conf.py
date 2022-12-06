#!/usr/bin/python3 -I
"""Generate krb5.conf snippet for consoleDot
"""
import logging
import os
import sys

from ipalib import api
from ipaplatform.paths import paths
from ipaserver.install.installutils import is_ipa_configured


SNIPPET = """\
[realms]
 {realm} = {{
  pkinit_anchors = FILE:{bundle_pem}
}}
"""

# TODO: remove file on uninstall
CONF_FILE = os.path.join(paths.COMMON_KRB5_CONF_DIR, "ipa-consoledot.conf")
BUNDLE_PEM = os.path.join(
    paths.USR_SHARE_IPA_DIR, "consoledot", "hmsidm-ca-bundle.pem"
)


def main():
    logging.basicConfig()
    if not is_ipa_configured():
        logging.info("IPA is not configured.")
        sys.exit(0)

    api.bootstrap()
    snippet = SNIPPET.format(
        realm=api.env.realm,
        bundle_pem=BUNDLE_PEM,
    )

    try:
        with open(CONF_FILE, "r") as f:
            content = f.read()
    except FileNotFoundError:
        content = ""

    if content != snippet:
        logging.info("Creating %s.", CONF_FILE)
        with open(CONF_FILE, "w") as f:
            f.write(snippet)
    else:
        logging.info("%s is up to date.", CONF_FILE)


if __name__ == "__main__":
    main()
