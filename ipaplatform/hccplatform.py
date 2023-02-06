#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat Hybrid Cloud Console
"""
import os
import logging

from ipaplatform.constants import constants

logger = logging.getLogger(__name__)


def _detect_environment(rhsm_conf="/etc/rhsm/rhsm.conf", default="prod"):
    """Detect environment (stage, prod) from RHSM server name

    TODO: Does not work, SELinux prevents read access from httpd_t
    to hsmcertd_config_t context::

       avc:  denied  { read } for  pid=34530 comm="httpd" name="rhsm.conf"
       dev="vda4" ino=8401286 scontext=system_u:system_r:httpd_t:s0
       tcontext=system_u:object_r:rhsmcertd_config_t:s0 tclass=file
       permissive=0

    """
    import configparser

    c = configparser.ConfigParser()
    try:
        with open(rhsm_conf) as f:
            c.read_file(f)
    except Exception as e:
        logger.error("Failed to read '%s': %s", rhsm_conf, e)
        return default

    server_hostname = c.get("server", "hostname", fallback=None)
    if server_hostname is None:
        return default

    server_hostname = server_hostname.strip()
    if server_hostname == "subscription.rhsm.redhat.com":
        return "prod"
    elif server_hostname == "subscription.rhsm.stage.redhat.com":
        return "stage"
    else:
        return default


# common constants and paths
HCC_SERVICE = u"hcc-enrollment"
HCC_SERVICE_USER = "ipahcc"
HCC_SERVICE_GROUP = getattr(constants, "IPAAPI_GROUP", "ipaapi")
HCC_SERVICE_CACHE_DIR = "/var/cache/ipa-hcc"

# IPA's gssproxy directory comes with correct SELinux rule.
HCC_SERVICE_KEYTAB = "/var/lib/ipa/gssproxy/hcc-enrollment.keytab"
HCC_SERVICE_KRB5CCNAME = "/var/cache/ipa-hcc/krb5ccname"

HCC_ENROLLMENT_ROLE = u"HCC Enrollment Administrators"

HMSIDM_CA_BUNDLE_PEM = "/usr/share/ipa-hcc/redhat-candlepin-bundle.pem"

HMSIDM_CACERTS_DIR = "/usr/share/ipa-hcc/cacerts"

RHSM_CERT = "/etc/pki/consumer/cert.pem"
RHSM_KEY = "/etc/pki/consumer/key.pem"

# Hybrid Cloud Console and Host Based Inventory API
# see https://access.redhat.com/articles/3626371
TOKEN_CLIENT_ID = "rhsm-api"
REFRESH_TOKEN_FILE = "/etc/ipa/hcc/refresh_token"
# if file is present, use stage URLs
STAGE_COOKIE_FILE = "/etc/ipa/hcc/stage"

# prod / stage
if os.path.isfile(STAGE_COOKIE_FILE):
    ENVIRONMENT = "stage"
else:
    ENVIRONMENT = "prod"

# fmt: off
if ENVIRONMENT == "prod":
    # production
    TOKEN_URL = (
        "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
    )
    INVENTORY_HOSTS_API = (
        "https://console.redhat.com/api/inventory/v1/hosts"
    )
    INVENTORY_HOSTS_CERT_API = (
        "https://cert.console.redhat.com/api/inventory/v1/hosts"
    )
else:
    TOKEN_URL = (
        "https://sso.stage.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
    )
    INVENTORY_HOSTS_API = (
        "https://console.stage.redhat.com/api/inventory/v1/hosts"
    )
    INVENTORY_HOSTS_CERT_API = (
        "https://cert.stage.console.redhat.com/api/inventory/v1/hosts"
    )
