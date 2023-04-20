from .baseldap import (
    LDAPObject as LDAPObject,
    LDAPRetrieve as LDAPRetrieve,
    LDAPUpdate as LDAPUpdate,
)

# from .selinuxusermap import validate_selinuxuser as validate_selinuxuser
from _typeshed import Incomplete

# from ipaserver.install.adtrust import (
#     set_and_check_netbios_name as set_and_check_netbios_name,
# )
# from ipaserver.plugins.privilege import (
#     principal_has_privilege as principal_has_privilege,
# )

logger: Incomplete
OPERATIONAL_ATTRIBUTES: Incomplete
DOMAIN_RESOLUTION_ORDER_SEPARATOR: str
register: Incomplete

def validate_search_records_limit(ugettext, value): ...

class config(LDAPObject):
    object_name: Incomplete
    default_attributes: Incomplete
    container_dn: Incomplete
    permission_filter_objectclasses: Incomplete
    managed_permissions: Incomplete
    label: Incomplete
    label_singular: Incomplete
    takes_params: Incomplete
    def get_dn(self, *keys, **kwargs): ...
    def update_entry_with_role_config(
        self, role_name, entry_attrs
    ) -> None: ...
    def show_servroles_attributes(
        self, entry_attrs, *roles, **options
    ) -> None: ...
    def gather_trusted_domains(self): ...
    def validate_domain_resolution_order(self, entry_attrs) -> None: ...

class config_mod(LDAPUpdate):
    __doc__: Incomplete
    def pre_callback(
        self, ldap, dn, entry_attrs, attrs_list, *keys, **options
    ): ...
    def exc_callback(
        self, keys, options, exc, call_func, *call_args, **call_kwargs
    ) -> None: ...
    def post_callback(self, ldap, dn, entry_attrs, *keys, **options): ...

class config_show(LDAPRetrieve):
    __doc__: Incomplete
    def post_callback(self, ldap, dn, entry_attrs, *keys, **options): ...
