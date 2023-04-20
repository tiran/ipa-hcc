#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat Hybrid Cloud Console
"""
__all__ = ("is_ipa_configured",)

import json
from configparser import ConfigParser

from ipalib.facts import is_ipa_configured
from ipaplatform.osinfo import osinfo
from ipaplatform.constants import constants
from ipapython.version import VENDOR_VERSION as IPA_VERSION

# version is updated by Makefile
VERSION = "0.9"

# common HTTP request headers
HTTP_HEADERS = {
    "User-Agent": f"IPA HCC auto-enrollment {VERSION} (IPA: {IPA_VERSION})",
    "X-RH-IDM-Version": json.dumps(
        {
            "ipa-hcc": VERSION,
            "ipa": IPA_VERSION,
            "os-release-id": osinfo["ID"],
            "os-release-version-id": osinfo["VERSION_ID"],
        }
    ),
}  # type: dict[str, str]

# HCC enrollment agent (part pf ipa-hcc-server-plugin)
# Note: IPA's gssproxy directory comes with correct SELinux rule.
HCC_ENROLLMENT_AGENT = "hcc-enrollment"
HCC_ENROLLMENT_AGENT_USER = "ipahcc"
HCC_ENROLLMENT_AGENT_GROUP = getattr(constants, "IPAAPI_GROUP", "ipaapi")
HCC_ENROLLMENT_AGENT_CACHE_DIR = "/var/cache/ipa-hcc"
HCC_ENROLLMENT_AGENT_KEYTAB = "/var/lib/ipa/gssproxy/hcc-enrollment.keytab"
HCC_ENROLLMENT_AGENT_KRB5CCNAME = "/var/cache/ipa-hcc/krb5ccname"

HCC_ENROLLMENT_ROLE = "HCC Enrollment Administrators"

HMSIDM_CACERTS_DIR = "/usr/share/ipa-hcc/cacerts"

RHSM_CERT = "/etc/pki/consumer/cert.pem"
RHSM_KEY = "/etc/pki/consumer/key.pem"
INSIGHTS_HOST_DETAILS = "/var/lib/insights/host-details.json"

# Hybrid Cloud Console and Host Based Inventory API
# see https://access.redhat.com/articles/3626371
TOKEN_CLIENT_ID = "rhsm-api"
REFRESH_TOKEN_FILE = "/etc/ipa/hcc/refresh_token"

# D-Bus API
# dbus doesn't like '-' in names
HCC_DBUS_NAME = "com.redhat.console.ipahcc"
HCC_DBUS_OBJ_PATH = "/com/redhat/console/ipahcc"
HCC_DBUS_IFACE_NAME = HCC_DBUS_NAME

# configuration
HCC_CONFIG = "/etc/ipa/hcc.conf"

HCC_DOMAIN_TYPE = "rhel-idm"

TEST_DOMAIN_ID = "772e9618-d0f8-4bf8-bfed-d2831f63c619"


class _HCCConfig:
    _defaults = {
        "hcc_api_host": "cert.console.redhat.com",
        "token_url": (
            "https://sso.redhat.com/auth/realms/redhat-external"
            "/protocol/openid-connect/token"
        ),
        "inventory_url": "https://console.redhat.com/api/inventory/v1",
    }

    _section = "hcc"

    def __init__(self):
        self._cp = ConfigParser(defaults=self._defaults)
        self._cp.add_section(self._section)
        self._cp.read(HCC_CONFIG)

    @property
    def hcc_api_host(self) -> str:
        return self._cp.get(self._section, "hcc_api_host")

    @property
    def token_url(self) -> str:
        return self._cp.get(self._section, "token_url")

    @property
    def inventory_url(self) -> str:
        return self._cp.get(self._section, "inventory_url")


_hccconfig = _HCCConfig()

HCC_API_HOST = _hccconfig.hcc_api_host
TOKEN_URL = _hccconfig.token_url
INVENTORY_URL = _hccconfig.inventory_url
