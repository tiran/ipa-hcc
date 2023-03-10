#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2023  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat Hybrid Cloud Console

Server roles and associated attribute extension.
"""
from ipalib import errors
from ipaplatform.hccplatform import text
from ipaserver import servroles
from ipaserver.plugins import serverroles
from ipaserver.plugins.serverrole import server_role

ipa_master_role = [
    role for role in servroles.role_instances if role.name == "IPA master"
][0]

# HCC enrollment server attribute is an IPA server role extension with
# ipaConfigString=hccEnrollmentEnabled in
# cn=HTTP,cn=$FQDH.test,cn=masters,cn=ipa,cn=etc,$SUFFIX
hcc_enrollment_server_attribute = servroles.ServerAttribute(
    text("hcc_enrollment_server_server"),
    text("HCC Enrollment enabled server"),
    ipa_master_role.attr_name,
    text("HTTP"),
    text("hccEnrollmentEnabled"),
)

hcc_update_server_attribute = servroles.SingleValuedServerAttribute(
    text("hcc_update_server_server"),
    text("HCC update server"),
    ipa_master_role.attr_name,
    text("HTTP"),
    text("hccUpdateServer"),
)

servroles.attribute_instances = tuple(
    list(servroles.attribute_instances)
    + [hcc_enrollment_server_attribute, hcc_update_server_attribute]
)

# serverroles module imports tuple from servroles
serverroles.attribute_instances = servroles.attribute_instances


def get_hcc_enrollment_servers(self):
    """Get set of server FQDNs with HCC Enrollment enabled"""
    backend = self.api.Backend.serverroles
    role_config = backend.config_retrieve(ipa_master_role.name)
    return set(role_config.get(hcc_enrollment_server_attribute.attr_name, ()))


def get_hcc_update_server(self):
    """Get FQDN of server that has the HCC update service enabled"""
    backend = self.api.Backend.serverroles
    role_config = backend.config_retrieve(ipa_master_role.name)
    return role_config.get(hcc_update_server_attribute.attr_name, None)


def set_hcc_enrollment_servers(self, servers):
    """Set servers with HCC Enrollment capabilities

    config_update() removes and adds at the same time.
    """
    backend = self.api.Backend.serverroles
    kwargs = {hcc_enrollment_server_attribute.attr_name: servers}
    try:
        backend.config_update(**kwargs)
    except errors.EmptyModlist:
        pass


def set_hcc_update_server(self, server):
    """Set server with HCC update server

    config_update() removes and adds at the same time.
    """
    backend = self.api.Backend.serverroles
    kwargs = {hcc_update_server_attribute.attr_name: server}
    try:
        backend.config_update(**kwargs)
    except errors.EmptyModlist:
        pass


server_role.get_hcc_enrollment_servers = get_hcc_enrollment_servers
server_role.get_hcc_update_server = get_hcc_update_server
server_role.set_hcc_enrollment_servers = set_hcc_enrollment_servers
server_role.set_hcc_update_server = set_hcc_update_server
