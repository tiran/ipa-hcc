#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat Hybrid Cloud Console
"""
from ipalib import _
from ipalib import errors
from ipalib.parameters import Int, Str

# pylint: disable=import-error
from ipaserver.plugins.config import config
from ipaserver.plugins.config import config_show
from ipaserver.plugins.config import config_mod
from ipaserver.plugins.internal import i18n_messages
from ipaserver.plugins.hccserverroles import hcc_enrollment_server_role

# pylint: enable=import-error

hcc_config_class = "hccconfig"

config.possible_objectclasses.append(hcc_config_class)

hcc_config_attributes = {
    "hccorgid",
    "hccdomainid",
}

config.default_attributes.extend(list(hcc_config_attributes))


takes_params = (
    Int(
        "hccorgid?",
        cli_name="hccorgid",
        label=_("HCC organization id"),
        minvalue=1,
    ),
    Str(
        "hccdomainid?",
        cli_name="hccdomainid",
        label=_("HCC domain id"),
    ),
    Str(
        "hcc_enrollment_server_server*",
        label=_("IPA servers capable of HCC auto-enrollment"),
        doc=_("IPA server which have HCC enrollment plugins"),
        flags={"virtual_attribute", "no_create"},
    ),
    Str(
        "hcc_enrollment_agent_server*",
        label=_("IPA servers with HCC enrollment agent"),
        doc=_("IPA server which can process HCC auto-enrollment requests"),
        flags={"virtual_attribute", "no_create"},
    ),
    Str(
        "hcc_update_server_server?",
        label=_("IPA server with HCC update service"),
        doc=_("IPA server which hosts the HCC update service"),
        flags={"virtual_attribute", "no_create"},
    ),
)

config.takes_params += takes_params


config.managed_permissions.update(
    {
        "System: Read HCC config attributes": {
            "replaces_global_anonymous_aci": True,
            "ipapermbindruletype": "all",
            "ipapermright": {"read", "search", "compare"},
            "ipapermtargetfilter": [
                "(objectclass={})".format(hcc_config_class)
            ],
            "ipapermdefaultattr": hcc_config_attributes,
        },
    },
)


# pylint: disable=unused-argument


def config_show_hcc_postcb(self, ldap, dn, entry_attrs, *keys, **options):
    self.obj.show_servroles_attributes(
        entry_attrs, hcc_enrollment_server_role.name, **options
    )
    return dn


config_show.register_post_callback(config_show_hcc_postcb)


def config_mod_hcc_precb(self, ldap, dn, entry, attrs_list, *keys, **options):
    if hcc_config_attributes.intersection(options):
        # add HCC object class
        if "objectclass" not in entry:
            entry_oc = ldap.get_entry(dn, ["objectclass"])
            entry["objectclass"] = entry_oc["objectclass"]
        if not self.obj.has_objectclass(
            entry["objectclass"], hcc_config_class
        ):
            entry["objectclass"].append(hcc_config_class)

    config_updates = {}

    if "hcc_update_server_server" in options:
        new_update = options["hcc_update_server_server"]
        try:
            self.api.Object.server.get_dn_if_exists(new_update)
        except errors.NotFound:
            raise self.api.Object.server.handle_not_found(new_update)
        config_updates["hcc_update_server_server"] = new_update

    if "hcc_enrollment_agent_server" in options:
        new_agents = options["hcc_enrollment_agent_server"]
        for agent in new_agents:
            try:
                self.api.Object.server.get_dn_if_exists(agent)
            except errors.NotFound:
                raise self.api.Object.server.handle_not_found(agent)
            config_updates["hcc_enrollment_agent_server"] = new_agents

    if config_updates:
        backend = self.api.Backend.serverroles
        backend.config_update(**config_updates)

    return dn


def config_mod_hcc_postcb(self, ldap, dn, entry_attrs, *keys, **options):
    self.obj.show_servroles_attributes(
        entry_attrs, hcc_enrollment_server_role.name, **options
    )
    return dn


def config_mod_hcc_exccb(
    self, keys, options, exc, call_func, *call_args, **call_kwargs
):
    if (
        isinstance(exc, errors.EmptyModlist)
        and call_func.__name__ == "update_entry"
        and (
            "hcc_update_server_server" in options
            or "hcc_enrollment_agent_server" in options
        )
    ):
        return
    else:
        raise exc


config_mod.register_pre_callback(config_mod_hcc_precb)
config_mod.register_post_callback(config_mod_hcc_postcb)
config_mod.register_exc_callback(config_mod_hcc_exccb)

i18n_messages.messages["hccconfig"] = {
    "name": _("Hybrid Cloud Console configuration")
}
