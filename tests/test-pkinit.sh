#!/bin/sh
set -ex

RHSM_ID=1f84492f-a824-41b8-8ccd-a4e9e1ab2f3d
HOSTNAME=hostc53b274ae54dc5dd.ipa.example

kdestroy -A
kinit \
    -X X509_user_identity=FILE:./clients/${RHSM_ID}.pem,./clients/${RHSM_ID}.key \
    host/${HOSTNAME}
klist
ipa host-show --all ${HOSTNAME}
