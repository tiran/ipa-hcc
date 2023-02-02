#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat Hybrid Cloud Console
"""
from ipaplatform.base.constants import User
from ipaplatform.constants import constants

# common constants and paths
HCC_SERVICE = "hcc-enrollment"
HCC_SERVICE_USER = User("ipahcc")
HCC_SERVICE_GROUP = constants.IPAAPI_GROUP
HCC_SERVICE_CACHE_DIR = "/var/cache/ipa-hcc"

# IPA's gssproxy directory comes with correct SELinux rule.
HCC_SERVICE_KEYTAB = "/var/lib/ipa/gssproxy/hcc-enrollment.keytab"
HCC_SERVICE_KRB5CCNAME = "/var/cache/ipa-hcc/krb5ccname"

HCC_ENROLLMENT_ROLE = "HCC Enrollment Administrators"

HMSIDM_CA_BUNDLE_PEM = "/usr/share/ipa-hcc/redhat-candlepin-bundle.pem"

HMSIDM_CACERTS_DIR = "/usr/share/ipa-hcc/cacerts"

RHSM_CERT = "/etc/pki/consumer/cert.pem"
RHSM_KEY = "/etc/pki/consumer/key.pem"

# Hybrid Cloud Console and Host Based Inventory API
# see https://access.redhat.com/articles/3626371
TOKEN_CLIENT_ID = "rhsm-api"
REFRESH_TOKEN_FILE = "/etc/ipa/hcc/refresh_token"

# prod / stage
TARGET = "prod"

# fmt: off
if TARGET == "prod":
    # production
    SSO_TOKEN_URL = (
        "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
    )
    INVENTORY_HOSTS_API = (
        "https://console.redhat.com/api/inventory/v1/hosts"
    )
    INVENTORY_HOSTS_CERT_API = (
        "https://cert.console.redhat.com/api/inventory/v1/hosts"
    )
elif TARGET == "stage":
    SSO_TOKEN_URL = (
        "https://sso.stage.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
    )
    INVENTORY_HOSTS_API = (
        "https://console.stage.redhat.com/api/inventory/v1/hosts"
    )
    INVENTORY_HOSTS_CERT_API = (
        "https://cert.stage.console.redhat.com/api/inventory/v1/hosts"
    )
