#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat Hybrid Cloud Console
"""
from ipalib import _
from ipalib.parameters import Int
from ipaserver.plugins.config import config
from ipaserver.plugins.config import config_mod
from ipaserver.plugins.internal import i18n_messages


hcc_config_class = "hccconfig"

if hcc_config_class not in config.possible_objectclasses:
    config.possible_objectclasses.append(hcc_config_class)

hcc_config_attributes = {
    "hccorgid",
}

config.default_attributes.extend(list(hcc_config_attributes))


takes_params = (
    Int(
        "hccorgid?",
        cli_name="hccorgid",
        label=_("HCC organization id"),
        minvalue=1,
    ),
)

config.takes_params += takes_params


config.managed_permissions.update(
    {
        "System: Read HCC config attributes": {
            "replaces_global_anonymous_aci": True,
            "ipapermbindruletype": "all",
            "ipapermright": {"read", "search", "compare"},
            "ipapermtargetfilter": [f"(objectclass={hcc_config_class})"],
            "ipapermdefaultattr": hcc_config_attributes,
        },
    },
)


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
    return dn


config_mod.register_pre_callback(config_mod_hcc_precb)

i18n_messages.messages["hccconfig"] = {
    "name": _("Hybrid Cloud Console configuration")
}
