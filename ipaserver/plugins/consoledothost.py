#
# IPA plugin for Red Hat consoleDot
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat consoleDot
"""
from ipalib import _
from ipalib import errors
from ipapython.dn import DN
from ipalib.parameters import Int, Str
from ipaserver.plugins.host import host
from ipaserver.plugins.host import host_add
from ipaserver.plugins.host import host_mod
from ipaserver.plugins.host import host_show
from ipaserver.plugins.internal import i18n_messages

UUID_RE = "[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"
UUID_ERRMSG = "must be an UUID"

consoledot_host_class = "consoledothost"

if consoledot_host_class not in host.possible_objectclasses:
    host.possible_objectclasses.append(consoledot_host_class)

consoledot_host_attributes = {
    "consoledotorgid",
    "consoledotsubscriptionid",
    "consoledotinventoryid",
    "consoledotcertsubject",
}

host.default_attributes.extend(list(consoledot_host_attributes))


takes_params = (
    Int(
        "consoledotorgid?",
        cli_name="consoledotorgid",
        label=_("organization id"),
        minvalue=1,
        maxvalue=255,
        # no_option?
        flags={"no_create", "no_update", "no_search"},
    ),
    Str(
        "consoledotsubscriptionid?",
        cli_name="consoledotsubscriptionid",
        label=_("subscription id"),
        pattern=UUID_RE,
        pattern_errmsg=UUID_ERRMSG,
        normalizer=lambda value: value.strip().lower(),
    ),
    Str(
        "consoledotinventoryid?",
        cli_name="consoledotinventoryid",
        label=_("inventory id"),
        pattern=UUID_RE,
        pattern_errmsg=UUID_ERRMSG,
        normalizer=lambda value: value.strip().lower(),
    ),
    Str(
        "consoledotcertsubject?",
        cli_name="consoledotcertsubject",
        label=_("RHSM certificate subject"),
        # no_option?
        flags={"no_create", "no_update", "no_search"},
    ),
)

host.takes_params += takes_params


host.managed_permissions.update(
    {
        "System: Read consoleDot host attributes": {
            "replaces_global_anonymous_aci": True,
            "ipapermbindruletype": "all",
            "ipapermright": {"read", "search", "compare"},
            "ipapermtargetfilter": [f"(objectclass={consoledot_host_class})"],
            "ipapermdefaultattr": consoledot_host_attributes,
        },
    },
)


def get_config_orgid(ldap):
    config = ldap.get_ipa_config()
    cfg_orgids = config.get("consoledotorgid")
    if len(cfg_orgids) == 1:
        return cfg_orgids[0]
    else:
        msg = _("consoleDot is not configured globally")
        # raises for subscription id
        raise errors.ValidationError(
            name="consoledotsubscriptionid", errors=msg
        )


def check_consoledot_attr(ldap, entry):
    """Common function to verify consoleDot host attributes"""
    subscriptionid = entry.get("consoledotsubscriptionid")
    if subscriptionid is not None:
        orgid = entry.get("consoledotorgid")
        if orgid is None:
            orgid = get_config_orgid(ldap)
            entry["consoledotorgid"] = orgid
        entry["consoledotcertsubject"] = str(
            DN(("O", orgid), ("CN", subscriptionid))
        )


def host_add_consoledot_precb(
    self, ldap, dn, entry, attrs_list, *keys, **options
):
    if consoledot_host_attributes.intersection(options):
        # add consoleDot object class
        if not self.obj.has_objectclass(
            entry["objectclass"], consoledot_host_class
        ):
            entry["objectclass"].append(consoledot_host_class)
        # check consoleDot attributes
        check_consoledot_attr(ldap, entry)
    return dn


host_add.register_pre_callback(host_add_consoledot_precb)


def host_mod_consoledot_precb(
    self, ldap, dn, entry, attrs_list, *keys, **options
):
    if consoledot_host_attributes.intersection(options):
        # add consoleDot object class
        if "objectclass" not in entry:
            entry_oc = ldap.get_entry(dn, ["objectclass"])
            entry["objectclass"] = entry_oc["objectclass"]
        if not self.obj.has_objectclass(
            entry["objectclass"], consoledot_host_class
        ):
            entry["objectclass"].append(consoledot_host_class)
        # check consoleDot attributes
        check_consoledot_attr(ldap, entry)
    return dn


host_mod.register_pre_callback(host_mod_consoledot_precb)

i18n_messages.messages["consoledothost"] = {"name": _("consoleDot host")}
