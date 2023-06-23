"""Interface to register or update domains with Hybrid Cloud Console
"""
import base64
import json
import logging
import typing
import uuid
from http.client import responses as http_responses

import requests
import requests.auth
import requests.exceptions
from ipalib import errors
from requests.structures import CaseInsensitiveDict

try:
    from ipalib.install.certstore import (  # pylint: disable=ungrouped-imports
        get_ca_certs,
    )
except ImportError:  # pragma: no cover

    def get_ca_certs(
        ldap,
        base_dn,
        compat_realm,
        compat_ipa_ca,
        filter_subject: typing.Optional[typing.Any] = None,
    ):  # pylint: disable=unused-argument
        raise NotImplementedError


from ipahcc import hccplatform

from . import schema
from .util import create_certinfo

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10
_missing = object()


class APIResult(typing.NamedTuple):
    id: str  # request / error id
    status_code: int  # HTTP status code or IPA errno (>= 900)
    reason: str  # HTTP reason or IPA exception name
    url: typing.Optional[str]  # remote URL or None
    headers: typing.Union[
        typing.Dict[str, str], CaseInsensitiveDict, None
    ]  # response header dict or None
    body: typing.Union[dict, str]  # response body (JSON str or object)
    exit_code: int  # exit code for CLI (0: ok)
    exit_message: str  # human readable error message for CLI

    @classmethod
    def genrid(cls) -> str:
        """Generate request / response / error id"""
        return str(uuid.uuid4())

    @classmethod
    def from_response(
        cls, response: requests.Response, exit_code: int, exit_message: str
    ) -> "APIResult":
        return cls(
            cls.genrid(),
            response.status_code,
            response.reason,
            response.url,
            response.headers,
            response.text,
            exit_code,
            exit_message,
        )

    @classmethod
    def from_dict(
        cls, dct: dict, status_code: int, exit_code: int, exit_message: str
    ) -> "APIResult":
        assert isinstance(dct, dict)
        text = json.dumps(dct, sort_keys=True)
        return cls(
            cls.genrid(),
            status_code,
            http_responses[status_code],
            None,
            {
                "content-type": "application/json",
                "content-length": str(len(text)),
            },
            text,
            exit_code,
            exit_message,
        )

    def asdict(self) -> dict:
        """Convert to dict with dict body"""
        d = self._asdict()
        d["body"] = self.json()
        return d

    def to_dbus(self) -> "APIResult":
        """Convert to D-Bus format"""
        headers = self.headers or {}
        url = self.url or ""
        body = self.body
        if isinstance(body, dict):
            body = json.dumps(body, sort_keys=True)
        return type(self)(
            self.id,
            self.status_code,
            self.reason,
            url,
            headers,
            body,
            self.exit_code,
            self.exit_message,
        )

    def json(self) -> dict:
        if isinstance(self.body, dict):
            return self.body
        else:
            return json.loads(self.body)


def _get_one(dct: dict, key: str, default=_missing) -> typing.Any:
    try:
        return dct[key][0]
    except (KeyError, IndexError):
        if default is _missing:
            raise
        return default


class APIError(Exception):
    """HCC D-Bus API error"""

    def __init__(self, apiresult: APIResult):
        super().__init__()
        self.result = apiresult

    def __str__(self):
        # remove newline in JSON
        # content = self.result.body.replace("\n", "")
        clsname = self.__class__.__name__
        return f"{clsname}: {self.result}"

    __repr__ = __str__

    def to_dbus(self) -> APIResult:
        return self.result.to_dbus()

    @classmethod
    def from_response(
        cls,
        response: requests.Response,
        exit_code: int = 2,
        exit_message: str = "Request failed",
    ) -> "APIError":
        """Construct exception for failed request response"""
        return cls(APIResult.from_response(response, exit_code, exit_message))

    @classmethod
    def not_found(
        cls,
        rhsm_id: str,
        response: requests.Response,
        exit_code: int = 2,
        exit_message: str = http_responses[404],
    ) -> "APIError":
        """RHSM_ID not found (404)"""
        status_code = 404
        reason = http_responses[status_code]
        content = {
            "status": status_code,
            "title": reason,
            "details": f"Host with owner id '{rhsm_id}' not found in inventory.",
        }
        return cls(
            APIResult(
                APIResult.genrid(),
                status_code,
                reason,
                response.url,
                response.headers,
                content,
                exit_code,
                exit_message,
            )
        )

    @classmethod
    def from_ipaerror(
        cls, e: Exception, exit_code: int, exit_message: str
    ) -> "APIError":
        """From public IPA, expected exception"""
        # does not handle errors.PrivateError
        assert isinstance(e, errors.PublicError)
        exc_name = type(e).__name__
        exc_msg = str(e)
        status_code = e.errno
        reason = f"{exc_name}: {exc_msg}"
        content = {
            "status_code": status_code,
            "title": exc_name,
            "details": exc_msg,
        }
        return cls(
            APIResult(
                APIResult.genrid(),
                status_code,
                reason,
                None,
                {"content-type": "application/json"},
                content,
                exit_code,
                exit_message,
            )
        )

    @classmethod
    def from_other(
        cls, status_code: int, exit_code: int, exit_message: str
    ) -> "APIError":
        """From generic error"""
        reason = http_responses[status_code]
        content = {
            "status_code": status_code,
            "title": reason,
            "details": exit_message,
        }
        return cls(
            APIResult(
                APIResult.genrid(),
                status_code,
                reason,
                None,
                {"content-type": "application/json"},
                content,
                exit_code,
                exit_message,
            )
        )


class HCCAPI:
    """Register or update domain information in HCC"""

    def __init__(self, api, timeout: int = DEFAULT_TIMEOUT):
        # if not api.isdone("finalize") or not api.env.in_server:
        #     raise ValueError(
        #         "api must be an in_server and finalized API object"
        #     )

        self.api = api
        self.timeout = timeout
        self.session = requests.Session()

    def __enter__(self) -> "HCCAPI":
        self.api.Backend.ldap2.connect(time_limit=self.timeout)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.api.Backend.ldap2.disconnect()

    def register_domain(
        self, domain_id: str, token: str
    ) -> typing.Tuple[dict, APIResult]:
        config = self._get_ipa_config(all_fields=True)
        info = self._get_ipa_info(config)
        schema.validate_schema(info, "IPADomainRequest")
        extra_headers = {
            "X-RH-IDM-Registration-Token": token,
        }
        resp = self._submit_idm_api(
            method="PUT",
            subpath=("domains", domain_id, "register"),
            payload=info,
            extra_headers=extra_headers,
        )
        schema.validate_schema(resp.json(), "IPADomainResponse")
        # update after successful registration
        try:
            self.api.Command.config_mod(hccdomainid=str(domain_id))
        except errors.EmptyModlist:
            logger.debug("hccdomainid=%s already configured", domain_id)
        else:
            logger.debug("hccdomainid=%s set", domain_id)
        msg = (
            f"Successfully registered domain '{info['domain_name']}' "
            f"with Hybrid Cloud Console (id: {domain_id})."
        )
        result = APIResult.from_response(resp, 0, msg)
        return info, result

    def update_domain(
        self, update_server_only: bool = False
    ) -> typing.Tuple[dict, APIResult]:
        config = self._get_ipa_config(all_fields=True)
        # hcc_update_server_server is a single attribute
        update_server = config.get("hcc_update_server_server")
        if update_server_only and update_server != self.api.env.host:
            # stop with success
            logger.info(
                "Current host is not an HCC update server (update server: %s)",
                update_server,
            )
            # TODO
            raise APIError.from_other(
                0, 0, "Current host is not an HCC update server"
            )

        domain_id = self._get_domain_id(config)

        info = self._get_ipa_info(config)
        schema.validate_schema(info, "IPADomainRequest")
        resp = self._submit_idm_api(
            method="PUT",
            subpath=("domains", domain_id, "update"),
            payload=info,
            extra_headers=None,
        )
        schema.validate_schema(resp.json(), "IPADomainResponse")
        msg = (
            f"Successfully updated domain '{info['domain_name']}' "
            f"({domain_id})."
        )
        result = APIResult.from_response(resp, 0, msg)
        return info, result

    def status_check(self) -> typing.Tuple[dict, APIResult]:
        config = self._get_ipa_config(all_fields=True)
        info = self._get_ipa_info(config)
        # remove CA certs, add domain and org id
        info[hccplatform.HCC_DOMAIN_TYPE].pop("ca_certs", None)
        domain_id = _get_one(config, "hccdomainid", None)
        org_id = _get_one(config, "hccorgid", default=None)
        info.update(domain_id=domain_id, org_id=org_id)
        if domain_id:
            msg = (
                f"IPA domain '{info['domain_name']}' is registered with Hybrid "
                f"Cloud Console (domain_id: {domain_id}, organization: {org_id})."
            )
        else:
            msg = "IPA domain is not registered."
        result = APIResult.from_dict(info, 200, 0, msg)
        return {}, result

    def _get_domain_id(self, config: typing.Dict[str, typing.Any]):
        domain_id = _get_one(config, "hccdomainid", None)
        if domain_id is None:
            raise APIError.from_other(
                500, 3, "Global setting 'hccDomainId' is missing."
            )
        return domain_id

    def _get_servers(
        self, config: typing.Dict[str, typing.Any]
    ) -> typing.List[typing.Dict[str, typing.Any]]:
        """Get list of IPA server info objects"""
        # roles and role attributes are in config and server-role plugin
        ca_servers = set(config.get("ca_server_server", ()))
        hcc_enrollment = set(config.get("hcc_enrollment_server_server", ()))
        hcc_update = config.get("hcc_update_server_server", None)
        pkinit_servers = set(config.get("pkinit_server_server", ()))

        # location and some role names are in server-find plugin
        servers = self.api.Command.server_find(all=True)
        location_map = {}
        for server in servers["result"]:
            fqdn = _get_one(server, "cn")
            loc = _get_one(server, "ipalocation_location", default=None)
            if loc is not None:
                location_map[fqdn] = loc.to_text()

        # subscription manager id is in host plugin
        hosts = self.api.Command.host_find(in_hostgroup="ipaservers")

        result = []
        for host in hosts["result"]:
            fqdn = _get_one(host, "fqdn")

            server_info = {
                "fqdn": fqdn,
                "ca_server": (fqdn in ca_servers),
                "hcc_enrollment_server": (fqdn in hcc_enrollment),
                "hcc_update_server": (fqdn == hcc_update),
                "pkinit_server": (fqdn in pkinit_servers),
            }
            # optional, non-NULL fields
            location = location_map.get(fqdn)
            if location is not None:
                server_info["location"] = location
            rhsm_id = _get_one(host, "hccsubscriptionid", default=None)
            if rhsm_id is not None:
                server_info["subscription_manager_id"] = rhsm_id

            result.append(server_info)

        return result

    def _get_ca_certs(self) -> typing.List[dict]:
        """Get list of trusted CA cert info objects"""
        try:
            result = self.api.Command.ca_is_enabled(version="2.107")
            ca_enabled = result["result"]
        except (errors.CommandError, errors.NetworkError):
            result = self.api.Command.env(server=True, version="2.0")
            ca_enabled = result["result"]["enable_ra"]

        certs = get_ca_certs(
            self.api.Backend.ldap2,
            self.api.env.basedn,
            self.api.env.realm,
            ca_enabled,
        )

        ca_certs = []
        for cert, nickname, trusted, _eku in certs:
            if not trusted:
                continue
            ca_certs.append(create_certinfo(cert, nickname))

        return ca_certs

    def _get_realm_domains(self) -> typing.List[str]:
        """Get list of realm domain names"""
        result = self.api.Command.realmdomains_show()
        return sorted(result["result"]["associateddomain"])

    def _get_locations(self) -> typing.List[typing.Dict[str, str]]:
        # location_find() does not return servers
        locations = self.api.Command.location_find()
        result = []
        for location in locations["result"]:
            loc = {
                "name": _get_one(location, "idnsname").to_text(),
            }
            # optional, non-NULL field
            description = _get_one(location, "description", default=None)
            if description is not None:
                loc["description"] = description
            result.append(loc)
        return result

    def _get_ipa_config(
        self, all_fields=False
    ) -> typing.Dict[str, typing.Any]:
        try:
            return self.api.Command.config_show(all=all_fields)["result"]
        except Exception as e:
            msg = "Unable to get global configuration from IPA"
            logger.exception(msg)
            raise APIError.from_ipaerror(e, 5, msg) from None

    def _get_ipa_info(self, config: typing.Dict[str, typing.Any]):
        return {
            "domain_name": self.api.env.domain,
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            hccplatform.HCC_DOMAIN_TYPE: {
                "realm_name": self.api.env.realm,
                "servers": self._get_servers(config),
                "ca_certs": self._get_ca_certs(),
                "realm_domains": self._get_realm_domains(),
                "locations": self._get_locations(),
            },
        }

    def _get_dev_headers(self):
        fake_identity = {
            "identity": {
                "account_number": "11111",
                "org_id": hccplatform.DEV_ORG_ID,
                "type": "System",
                "auth_type": "cert-auth",
                "system": {
                    "cert_type": "system",
                    "cn": hccplatform.DEV_CERT_CN,
                },
                "internal": {
                    "auth_time": 900,
                    "cross_access": False,
                    "org_id": hccplatform.DEV_ORG_ID,
                },
            }
        }
        return {
            "X-Rh-Insights-Request-Id": str(uuid.uuid4()),
            "X-Rh-Fake-Identity": base64.b64encode(
                json.dumps(fake_identity).encode("utf-8")
            ),
        }

    def _submit_idm_api(
        self,
        method: str,
        subpath: tuple,
        payload: typing.Dict[str, typing.Any],
        extra_headers=None,
    ) -> requests.Response:
        api_url = hccplatform.IDM_API_URL.rstrip("/")
        url = "/".join((api_url,) + subpath)
        headers = {}
        headers.update(hccplatform.HTTP_HEADERS)
        if extra_headers:
            headers.update(extra_headers)

        if hccplatform.DEV_CERT_CN is not None:
            logger.warning(
                "Using dev X-Rh-Fake-Identity O=%s,CN=%s",
                hccplatform.DEV_ORG_ID,
                hccplatform.DEV_CERT_CN,
            )
            headers.update(self._get_dev_headers())

        if hccplatform.DEV_USERNAME and hccplatform.DEV_PASSWORD:
            logger.warning(
                "Using dev basic auth with account '%s'",
                hccplatform.DEV_USERNAME,
            )
            auth = requests.auth.HTTPBasicAuth(
                hccplatform.DEV_USERNAME,
                hccplatform.DEV_PASSWORD,
            )
            cert = None
        else:
            auth = None
            cert = (hccplatform.RHSM_CERT, hccplatform.RHSM_KEY)

        logger.debug("Sending %s request to %s", method, url)
        logger.debug("headers: %s", headers)
        body = json.dumps(payload, indent=2)
        logger.debug("body: %s", body)
        try:
            resp = self.session.request(
                method,
                url,
                headers=headers,
                timeout=self.timeout,
                auth=auth,
                cert=cert,
                json=payload,
            )
        except Exception as e:
            # TODO: better error handling
            raise APIError.from_other(500, 2, str(e)) from None
        try:
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(
                "Request to %s failed: %s: %s", url, type(e).__name__, e
            )
            raise APIError.from_response(
                resp, 4, f"{method} request failed"
            ) from None
        else:
            logger.debug("response: %s", json.dumps(resp.json(), indent=2))
            return resp
