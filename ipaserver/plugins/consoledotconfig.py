#
# IPA plugin for Red Hat consoleDot
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat consoleDot
"""
from ipalib import _
from ipalib.parameters import Int
from ipaserver.plugins.config import config
from ipaserver.plugins.config import config_mod
from ipaserver.plugins.internal import i18n_messages

consoledot_config_class = "consoledotconfig"

if consoledot_config_class not in config.possible_objectclasses:
    config.possible_objectclasses.append(consoledot_config_class)

consoledot_config_attributes = {
    "consoledotorgid",
}

config.default_attributes.extend(list(consoledot_config_attributes))


takes_params = (
    Int(
        "consoledotorgid?",
        cli_name="consoledotorgid",
        label=_("organization id"),
        minvalue=1,
    ),
)

config.takes_params += takes_params


config.managed_permissions.update(
    {
        "System: Read consoleDot config attributes": {
            "replaces_global_anonymous_aci": True,
            "ipapermbindruletype": "all",
            "ipapermright": {"read", "search", "compare"},
            "ipapermtargetfilter": [
                f"(objectclass={consoledot_config_class})"
            ],
            "ipapermdefaultattr": consoledot_config_attributes,
        },
    },
)


def config_mod_consoledot_precb(
    self, ldap, dn, entry, attrs_list, *keys, **options
):
    if consoledot_config_attributes.intersection(options):
        # add consoleDot object class
        if "objectclass" not in entry:
            entry_oc = ldap.get_entry(dn, ["objectclass"])
            entry["objectclass"] = entry_oc["objectclass"]
        if not self.obj.has_objectclass(
            entry["objectclass"], consoledot_config_class
        ):
            entry["objectclass"].append(consoledot_config_class)
    return dn


config_mod.register_pre_callback(config_mod_consoledot_precb)

i18n_messages.messages["consoledotconfig"] = {
    "name": _("consoleDot configuration")
}
