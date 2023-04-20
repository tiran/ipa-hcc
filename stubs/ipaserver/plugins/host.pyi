from .baseldap import (
    LDAPAddAttribute as LDAPAddAttribute,
    LDAPAddAttributeViaOption as LDAPAddAttributeViaOption,
    LDAPAddMember as LDAPAddMember,
    LDAPCreate as LDAPCreate,
    LDAPDelete as LDAPDelete,
    LDAPObject as LDAPObject,
    LDAPQuery as LDAPQuery,
    LDAPRemoveAttribute as LDAPRemoveAttribute,
    LDAPRemoveAttributeViaOption as LDAPRemoveAttributeViaOption,
    LDAPRemoveMember as LDAPRemoveMember,
    LDAPRetrieve as LDAPRetrieve,
    LDAPSearch as LDAPSearch,
    LDAPUpdate as LDAPUpdate,
    add_missing_object_class as add_missing_object_class,
    host_is_master as host_is_master,
    pkey_to_value as pkey_to_value,
)

# from .dns import (
#     add_records_for_host as add_records_for_host,
#     add_records_for_host_validation as add_records_for_host_validation,
#     dns_container_exists as dns_container_exists,
#     get_reverse_zone as get_reverse_zone,
# )
# from .service import (
#     normalize_principal as normalize_principal,
#     rename_ipaallowedtoperform_from_ldap as rename_ipaallowedtoperform_from_ldap,
#     rename_ipaallowedtoperform_to_ldap as rename_ipaallowedtoperform_to_ldap,
#     revoke_certs as revoke_certs,
#     set_certificate_attrs as set_certificate_attrs,
#     set_kerberos_attrs as set_kerberos_attrs,
#     ticket_flags_params as ticket_flags_params,
#     update_krbticketflags as update_krbticketflags,
#     validate_auth_indicator as validate_auth_indicator,
#     validate_realm as validate_realm,
# )
from _typeshed import Incomplete
from collections.abc import Generator
from ipalib import Str

unicode = str
logger: Incomplete
register: Incomplete

def remove_ptr_rec(ipaddr, fqdn): ...
def update_sshfp_record(zone, record, entry_attrs) -> None: ...
def convert_ipaassignedidview_post(entry_attrs, options) -> None: ...

host_output_params: Incomplete

def validate_ipaddr(ugettext, ipaddr): ...
def resolve_fqdn(name): ...

class HostPassword(Str):
    kwargs: Incomplete
    def safe_value(self, value): ...

class host(LDAPObject):
    container_dn: Incomplete
    object_name: Incomplete
    object_name_plural: Incomplete
    object_class: Incomplete
    possible_objectclasses: Incomplete
    permission_filter_objectclasses: Incomplete
    search_attributes: Incomplete
    default_attributes: Incomplete
    uuid_attribute: str
    attribute_members: Incomplete
    bindable: bool
    relationships: Incomplete
    password_attributes: Incomplete
    managed_permissions: Incomplete
    label: Incomplete
    label_singular: Incomplete
    takes_params: Incomplete
    def get_dn(self, *keys, **options): ...
    def get_managed_hosts(self, dn): ...
    def suppress_netgroup_memberof(self, ldap, entry_attrs) -> None: ...

class host_add(LDAPCreate):
    __doc__: Incomplete
    has_output_params: Incomplete
    msg_summary: Incomplete
    member_attributes: Incomplete
    takes_options: Incomplete
    def pre_callback(
        self, ldap, dn, entry_attrs, attrs_list, *keys, **options
    ): ...
    def post_callback(self, ldap, dn, entry_attrs, *keys, **options): ...

class host_del(LDAPDelete):
    __doc__: Incomplete
    msg_summary: Incomplete
    member_attributes: Incomplete
    takes_options: Incomplete
    def pre_callback(self, ldap, dn, *keys, **options): ...

class host_mod(LDAPUpdate):
    __doc__: Incomplete
    has_output_params: Incomplete
    msg_summary: Incomplete
    member_attributes: Incomplete
    takes_options: Incomplete
    def pre_callback(
        self, ldap, dn, entry_attrs, attrs_list, *keys, **options
    ): ...
    def post_callback(self, ldap, dn, entry_attrs, *keys, **options): ...

class host_find(LDAPSearch):
    __doc__: Incomplete
    has_output_params: Incomplete
    msg_summary: Incomplete
    member_attributes: Incomplete
    def get_options(self) -> Generator[Incomplete, None, None]: ...
    def pre_callback(
        self, ldap, filter, attrs_list, base_dn, scope, *args, **options
    ): ...
    def post_callback(self, ldap, entries, truncated, *args, **options): ...

class host_show(LDAPRetrieve):
    __doc__: Incomplete
    has_output_params: Incomplete
    takes_options: Incomplete
    member_attributes: Incomplete
    def pre_callback(self, ldap, dn, attrs_list, *keys, **options): ...
    def post_callback(self, ldap, dn, entry_attrs, *keys, **options): ...

class host_disable(LDAPQuery):
    __doc__: Incomplete
    has_output: Incomplete
    msg_summary: Incomplete
    def execute(self, *keys, **options): ...
    def post_callback(self, ldap, dn, entry_attrs, *keys, **options): ...

class host_add_managedby(LDAPAddMember):
    __doc__: Incomplete
    member_attributes: Incomplete
    has_output_params: Incomplete
    allow_same: bool
    def post_callback(
        self, ldap, completed, failed, dn, entry_attrs, *keys, **options
    ): ...

class host_remove_managedby(LDAPRemoveMember):
    __doc__: Incomplete
    member_attributes: Incomplete
    has_output_params: Incomplete
    def post_callback(
        self, ldap, completed, failed, dn, entry_attrs, *keys, **options
    ): ...

class host_allow_retrieve_keytab(LDAPAddMember):
    __doc__: Incomplete
    member_attributes: Incomplete
    has_output_params: Incomplete
    def pre_callback(self, ldap, dn, found, not_found, *keys, **options): ...
    def post_callback(
        self, ldap, completed, failed, dn, entry_attrs, *keys, **options
    ): ...

class host_disallow_retrieve_keytab(LDAPRemoveMember):
    __doc__: Incomplete
    member_attributes: Incomplete
    has_output_params: Incomplete
    def pre_callback(self, ldap, dn, found, not_found, *keys, **options): ...
    def post_callback(
        self, ldap, completed, failed, dn, entry_attrs, *keys, **options
    ): ...

class host_allow_create_keytab(LDAPAddMember):
    __doc__: Incomplete
    member_attributes: Incomplete
    has_output_params: Incomplete
    def pre_callback(self, ldap, dn, found, not_found, *keys, **options): ...
    def post_callback(
        self, ldap, completed, failed, dn, entry_attrs, *keys, **options
    ): ...

class host_disallow_create_keytab(LDAPRemoveMember):
    __doc__: Incomplete
    member_attributes: Incomplete
    has_output_params: Incomplete
    def pre_callback(self, ldap, dn, found, not_found, *keys, **options): ...
    def post_callback(
        self, ldap, completed, failed, dn, entry_attrs, *keys, **options
    ): ...

class host_add_cert(LDAPAddAttributeViaOption):
    __doc__: Incomplete
    msg_summary: Incomplete
    attribute: str

class host_remove_cert(LDAPRemoveAttributeViaOption):
    __doc__: Incomplete
    msg_summary: Incomplete
    attribute: str
    def post_callback(self, ldap, dn, entry_attrs, *keys, **options): ...

class host_add_principal(LDAPAddAttribute):
    __doc__: Incomplete
    msg_summary: Incomplete
    attribute: str
    def pre_callback(
        self, ldap, dn, entry_attrs, attrs_list, *keys, **options
    ): ...

class host_remove_principal(LDAPRemoveAttribute):
    __doc__: Incomplete
    msg_summary: Incomplete
    attribute: str
    def pre_callback(
        self, ldap, dn, entry_attrs, attrs_list, *keys, **options
    ): ...
