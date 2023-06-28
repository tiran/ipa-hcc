#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat Hybrid Cloud Console
"""
from ipalib import _, errors
from ipalib.parameters import Str
from ipapython.dn import DN

# pylint: disable=import-error
from ipaserver.plugins.host import host, host_add, host_mod
from ipaserver.plugins.internal import i18n_messages

# pylint: enable=import-error

UUID_RE = "[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"
UUID_ERRMSG = "must be an UUID"

hcc_host_class = "hcchost"

host.possible_objectclasses.append(hcc_host_class)

hcc_host_attributes = {
    "hccorgid",
    "hccsubscriptionid",
    "hccinventoryid",
    "hcccertsubject",
}

host.default_attributes.extend(list(hcc_host_attributes))


takes_params = (
    Str(
        "hccorgid?",
        cli_name="hccorgid",
        label=_("HCC organization id"),
        # no_option?
        flags={"no_create", "no_update", "no_search"},
    ),
    Str(
        "hccsubscriptionid?",
        cli_name="hccsubscriptionid",
        label=_("HCC subscription id"),
        pattern=UUID_RE,
        pattern_errmsg=UUID_ERRMSG,
        normalizer=lambda value: value.strip().lower(),
    ),
    Str(
        "hccinventoryid?",
        cli_name="hccinventoryid",
        label=_("HCC inventory id"),
        pattern=UUID_RE,
        pattern_errmsg=UUID_ERRMSG,
        normalizer=lambda value: value.strip().lower(),
    ),
    Str(
        "hcccertsubject?",
        cli_name="hcccertsubject",
        label=_("RHSM certificate subject"),
        # no_option?
        flags={"no_create", "no_update", "no_search"},
    ),
)

host.takes_params += takes_params


host.managed_permissions.update(
    {
        "System: Read HCC host attributes": {
            "replaces_global_anonymous_aci": True,
            "ipapermbindruletype": "all",
            "ipapermright": {"read", "search", "compare"},
            "ipapermtargetfilter": [f"(objectclass={hcc_host_class})"],
            "ipapermdefaultattr": hcc_host_attributes,
        },
        "System: Modify HCC host attributes": {
            "ipapermright": {"write"},
            "ipapermdefaultattr": hcc_host_attributes,
            "default_privileges": {"Host Administrators"},
        },
    },
)


# pylint: disable=unused-argument
def get_config_orgid(ldap):
    config = ldap.get_ipa_config()
    cfg_orgids = config.get("hccorgid")
    if cfg_orgids is None or len(cfg_orgids) != 1:
        msg = _("HCC org id is not configured globally")
        # raises for subscription id
        raise errors.ValidationError(name="hccsubscriptionid", errors=msg)
    else:
        return cfg_orgids[0]


def check_hcc_attr(ldap, dn, entry):
    """Common function to verify HCC host attributes"""
    subscriptionid = entry.get("hccsubscriptionid")
    if subscriptionid is not None:
        orgid = entry.get("hccorgid")
        if orgid is None:
            orgid = get_config_orgid(ldap)
            entry["hccorgid"] = orgid
        entry["hcccertsubject"] = str(
            DN(("O", orgid), ("CN", subscriptionid))
        )
    else:
        entry.pop("hccorgid")
        entry.pop("hcccertsubject")


def host_add_hcc_precb(self, ldap, dn, entry, attrs_list, *keys, **options):
    if hcc_host_attributes.intersection(options):
        # add HCC object class
        if not self.obj.has_objectclass(entry["objectclass"], hcc_host_class):
            entry["objectclass"].append(hcc_host_class)
        # check HCC attributes
        check_hcc_attr(ldap, dn, entry)
    return dn


host_add.register_pre_callback(host_add_hcc_precb)


def host_mod_hcc_precb(self, ldap, dn, entry, attrs_list, *keys, **options):
    if hcc_host_attributes.intersection(options):
        # add HCC object class
        if "objectclass" not in entry:
            entry_oc = ldap.get_entry(dn, ["objectclass"])
            entry["objectclass"] = entry_oc["objectclass"]
        if not self.obj.has_objectclass(entry["objectclass"], hcc_host_class):
            entry["objectclass"].append(hcc_host_class)
        # check HCC attributes
        check_hcc_attr(ldap, dn, entry)
    return dn


host_mod.register_pre_callback(host_mod_hcc_precb)

i18n_messages.messages["hcchost"] = {
    "name": _("Hybrid Cloud Console host"),
    "inventory": _("Hybrid Cloud Console inventory"),
}
