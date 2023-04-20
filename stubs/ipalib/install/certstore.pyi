from _typeshed import Incomplete
from ipalib import errors as errors, x509 as x509

def init_ca_entry(entry, cert, nickname, trusted, ext_key_usage) -> None: ...
def update_compat_ca(ldap, base_dn, cert) -> None: ...
def clean_old_config(
    ldap, base_dn, dn, config_ipa, config_compat
) -> None: ...
def add_ca_cert(
    ldap,
    base_dn,
    cert,
    nickname,
    trusted: Incomplete | None = ...,
    ext_key_usage: Incomplete | None = ...,
    config_ipa: bool = ...,
    config_compat: bool = ...,
) -> None: ...
def update_ca_cert(
    ldap,
    base_dn,
    cert,
    trusted: Incomplete | None = ...,
    ext_key_usage: Incomplete | None = ...,
    config_ipa: bool = ...,
    config_compat: bool = ...,
) -> None: ...
def put_ca_cert(
    ldap,
    base_dn,
    cert,
    nickname,
    trusted: Incomplete | None = ...,
    ext_key_usage: Incomplete | None = ...,
    config_ipa: bool = ...,
    config_compat: bool = ...,
) -> None: ...
def make_compat_ca_certs(certs, realm, ipa_ca_subject): ...
def get_ca_certs(
    ldap,
    base_dn,
    compat_realm,
    compat_ipa_ca,
    filter_subject: Incomplete | None = ...,
): ...
def trust_flags_to_key_policy(trust_flags): ...
def key_policy_to_trust_flags(trusted, ca, ext_key_usage): ...
def put_ca_cert_nss(
    ldap,
    base_dn,
    cert,
    nickname,
    trust_flags,
    config_ipa: bool = ...,
    config_compat: bool = ...,
) -> None: ...
def get_ca_certs_nss(
    ldap,
    base_dn,
    compat_realm,
    compat_ipa_ca,
    filter_subject: Incomplete | None = ...,
): ...
def get_ca_subject(ldap, container_ca, base_dn): ...
