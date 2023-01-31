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

# IPA's gssproxy directory comes with correct SELinux rule.
HCC_SERVICE_KEYTAB = "/var/lib/ipa/gssproxy/hcc-enrollment.keytab"
HCC_SERVICE_KRB5CCNAME = "/var/cache/ipa-hcc/krb5ccname"

HCC_ENROLLMENT_ROLE = "HCC Enrollment Administrators"

HMSIDM_CA_BUNDLE_PEM = "/usr/share/ipa-hcc/redhat-candlepin-bundle.pem"

HMSIDM_CACERTS_DIR = "/usr/share/ipa-hcc/cacerts"

RHSM_CERT = "/etc/pki/consumer/cert.pem"
RHSM_KEY = "/etc/pki/consumer/key.pem"
