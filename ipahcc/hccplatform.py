#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat Hybrid Cloud Console
"""
import logging
import sys

from ipaplatform.constants import constants

logger = logging.getLogger(__name__)


PY2 = sys.version_info.major == 2

if PY2:
    text = unicode  # noqa: F821
    from ConfigParser import SafeConfigParser as ConfigParser  # noqa: F821
    from ConfigParser import NoOptionError  # noqa: F821
else:
    text = str
    from configparser import ConfigParser, NoOptionError

# common constants and paths
HCC_SERVICE = text("hcc-enrollment")
HCC_SERVICE_USER = "ipahcc"
HCC_SERVICE_GROUP = getattr(constants, "IPAAPI_GROUP", "ipaapi")
HCC_SERVICE_CACHE_DIR = "/var/cache/ipa-hcc"

# IPA's gssproxy directory comes with correct SELinux rule.
HCC_SERVICE_KEYTAB = "/var/lib/ipa/gssproxy/hcc-enrollment.keytab"
HCC_SERVICE_KRB5CCNAME = "/var/cache/ipa-hcc/krb5ccname"

HCC_ENROLLMENT_ROLE = text("HCC Enrollment Administrators")

HMSIDM_CA_BUNDLE_PEM = "/usr/share/ipa-hcc/redhat-candlepin-bundle.pem"

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

# XXX for internal testing
TEST_DOMAIN_ID = "772e9618-d0f8-4bf8-bfed-d2831f63c619"


class HCCConfig:
    _defaults = {
        "environment": "prod",
        "refresh_token": "",
    }

    _token_url = "https://sso.{base}/auth/realms/redhat-external/protocol/openid-connect/token"
    _inventory_hosts_api = "https://console.{base}/api/inventory/v1/hosts"
    _inventory_hosts_cert_api = (
        "https://cert.console.{base}/api/inventory/v1/hosts"
    )
    _idm_cert_api = "https://cert.console.{base}/api/idm/v1"

    _section = "hcc"

    def __init__(self):
        self._cp = ConfigParser(defaults=self._defaults)
        self._cp.add_section(self._section)
        self._cp.read(HCC_CONFIG)
        self._environment = self._cp.get(self._section, "environment")
        if self._environment == "prod":
            self._base = "redhat.com"
        elif self._environment == "stage":
            self._base = "stage.redhat.com"
        else:
            raise ValueError(
                "Invalid environment {}".format(self._environment)
            )

    @property
    def environment(self):
        return self._environment

    @property
    def idm_cert_api_url(self):
        try:
            return self._cp.get(self._section, "idm_cert_api_url")
        except NoOptionError:
            return self._idm_cert_api.format(base=self._base)

    @property
    def token_url(self):
        return self._token_url.format(base=self._base)

    @property
    def inventory_hosts_api(self):
        return self._inventory_hosts_api.format(base=self._base)

    @property
    def inventory_hosts_cert_api(self):
        return self._inventory_hosts_cert_api.format(base=self._base)
