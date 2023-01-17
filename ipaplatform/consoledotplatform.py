#
# IPA plugin for Red Hat consoleDot
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat consoleDot
"""
from ipaplatform.base.constants import User
from ipaplatform.constants import constants

# common constants and paths
CONSOLEDOT_SERVICE = "consoledot-enrollment"
CONSOLEDOT_SERVICE_USER = User("ipaconsoledot")
CONSOLEDOT_SERVICE_GROUP = constants.IPAAPI_GROUP

# IPA's gssproxy directory comes with correct SELinux rule.
CONSOLEDOT_SERVICE_KEYTAB = (
    "/var/lib/ipa/gssproxy/consoledot-enrollment.keytab"
)
CONSOLEDOT_SERVICE_KRB5CCNAME = "/var/cache/ipa-consoledot/krb5ccname"

CONSOLEDOT_ENROLLMENT_ROLE = "consoleDot Enrollment Administrators"

HMSIDM_CA_BUNDLE_PEM = "/usr/share/ipa-consoledot/hmsidm-ca-bundle.pem"

HMSIDM_CACERTS_DIR = "/usr/share/ipa-consoledot/cacerts"

RHSM_CERT = "/etc/pki/consumer/cert.pem"
RHSM_KEY = "/etc/pki/consumer/key.pem"
