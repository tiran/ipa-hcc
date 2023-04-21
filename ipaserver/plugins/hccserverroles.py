#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2023  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat Hybrid Cloud Console

Server roles and associated attribute extension.
"""
from ipalib import api, errors
from ipaplatform.base import services as base_services
from ipaplatform.fedora import services as fed_services
from ipaplatform.redhat import services as rh_services

# pylint: disable=import-error
from ipaserver import masters, servroles
from ipaserver.plugins import serverroles
from ipaserver.plugins.serverrole import server_role

# pylint: enable=import-error

# service definitions, used by ipactl to start systemd services and for
# service-based server role.
# dbus API, cn=IPAHCCDBus,cn=$FQDN,cn=masters,cn=ipa,cn=etc,$SUFFIX
ipa_hcc_dbus = masters.service_definition(
    systemd_name="ipa-hcc-dbus",
    startorder=45,  # start after HTTPD
    service_entry="IPAHCCDBus",
)
# timer service, cn=IPAHCCUpdate,cn=$FQDN,cn=masters,cn=ipa,cn=etc,$SUFFIX
ipa_hcc_update = masters.service_definition(
    systemd_name="ipa-hcc-update",
    startorder=46,
    service_entry="IPAHCCUpdate",
)

ipa_hcc_services = [ipa_hcc_dbus, ipa_hcc_update]
ipa_hcc_systemd_names = [s.systemd_name for s in ipa_hcc_services]
ipa_hcc_service_entries = {s.service_entry: s for s in ipa_hcc_services}
ipa_hcc_units = {
    ipa_hcc_dbus.systemd_name: f"{ipa_hcc_dbus.systemd_name}.service",
    ipa_hcc_update.systemd_name: f"{ipa_hcc_update.systemd_name}.timer",
}
ipa_hcc_knownservices = {
    name: rh_services.RedHatService(srv, api=api)
    for name, srv in ipa_hcc_units.items()
}

# patch ipaserver.masters
masters.SERVICES.extend(ipa_hcc_services)
masters.SERVICE_LIST.update(ipa_hcc_service_entries)

# patch ipaplatform.services
base_services.wellknownservices.extend(ipa_hcc_systemd_names)
rh_services.redhat_system_units.update(ipa_hcc_units)
fed_services.fedora_system_units.update(ipa_hcc_units)
# pylint: disable=protected-access
rh_services.knownservices._KnownServices__d.update(ipa_hcc_knownservices)
fed_services.knownservices._KnownServices__d.update(ipa_hcc_knownservices)
# pylint: enable=protected-access

hcc_enrollment_server_role = servroles.ServiceBasedRole(
    "hcc_enrollment_server_server",
    "HCC Enrollment server",
    component_services=sorted(ipa_hcc_service_entries),
)

# HCC enrollment agent and update server attributes are server role
# attributes with 'ipaConfigString=hccEnrollmentAgentEnabled; in
# cn=IPAHCCDBus,cn=$FQDN.test,cn=masters,cn=ipa,cn=etc,$SUFFIX
hcc_enrollment_agent_attribute = servroles.ServerAttribute(
    "hcc_enrollment_agent_server",
    "HCC enrollment agent server",
    hcc_enrollment_server_role.attr_name,
    ipa_hcc_dbus.service_entry,
    "hccEnrollmentAgentEnabled",
)

# only one server in a topology runs the update service
# cn=IPAHCCUpdate,cn=$FQDN.test,cn=masters,cn=ipa,cn=etc,$SUFFIX
hcc_update_server_attribute = servroles.SingleValuedServerAttribute(
    "hcc_update_server_server",
    "HCC prime update server",
    hcc_enrollment_server_role.attr_name,
    ipa_hcc_update.service_entry,
    "hccUpdateServer",
)

# patch ipaserver.servroles
servroles.role_instances = tuple(
    list(servroles.role_instances) + [hcc_enrollment_server_role]
)
servroles.attribute_instances = tuple(
    list(servroles.attribute_instances)
    + [hcc_enrollment_agent_attribute, hcc_update_server_attribute]
)
# serverroles module imports tuples from servroles
serverroles.role_instances = servroles.role_instances
serverroles.attribute_instances = servroles.attribute_instances


def get_hcc_enrollment_agents(self):
    """Get set of server FQDNs with HCC enrollment agents enabled"""
    backend = self.api.Backend.serverroles
    role_config = backend.config_retrieve(hcc_enrollment_server_role.name)
    return set(role_config.get(hcc_enrollment_agent_attribute.attr_name, ()))


def get_hcc_update_server(self):
    """Get FQDN of server that has the HCC update service enabled"""
    backend = self.api.Backend.serverroles
    role_config = backend.config_retrieve(hcc_enrollment_server_role.name)
    return role_config.get(hcc_update_server_attribute.attr_name, None)


def set_hcc_enrollment_agents(self, servers):
    """Set servers with HCC Enrollment capabilities

    config_update() removes and adds at the same time.
    """
    backend = self.api.Backend.serverroles
    kwargs = {hcc_enrollment_agent_attribute.attr_name: servers}
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


server_role.get_hcc_enrollment_agents = get_hcc_enrollment_agents  # type: ignore
server_role.get_hcc_update_server = get_hcc_update_server  # type: ignore
server_role.set_hcc_enrollment_agents = set_hcc_enrollment_agents  # type: ignore
server_role.set_hcc_update_server = set_hcc_update_server  # type: ignore
