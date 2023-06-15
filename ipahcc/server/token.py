"""Client token verification

Creates a JWS token (a JWT in JSON representation with multiple signatures).

JWK (JSON Web Key)
==================

- only key type (kty) "EC"
- crv must be either "P-256" or "P-348" (FIPS approved curved)
- key identifier (kid) is set to thumbprint
- additional key 'exp' with key expiration time

JWT (JSON Web Token)
====================

JWT must be signed (JWS):
  - headers "kid" and "alg" must be set
  - alg is either "ES256" or "ES384" (ECDSA signature with SHA-256/384)
  - only a single signature is currently handled (no JWKS yet)

Registered claims:
  - issuer (iss) must be "https://console.redhat.com/api/idm"
  - subject (sub) is RHSM cert subject "CN"
  - aud (audience) must be "register host"
  - expiration (exp), not before (nbf), and issued at (iat) must be set
  - JWT ID (jti) must be set (e.g. random uuid4)

Additional private claims:
  - "idm_org_id" (string) is set to RHSM cert subject "O"
  - "idm_inventory_id" (string) is host-based inventory uuid
"""
import base64
import os
import time
import typing

from jwcrypto import jwk, jws, jwt
from jwcrypto.common import (
    JWException,
    json_decode,
    json_encode,
)

# EC key curve to algorighm mapping
KTY = "EC"
CRV_TO_ALG = {
    "P-256": "ES256",
    "P-384": "ES384",
}
SUPPORTED_ALGS = set(CRV_TO_ALG.values())

# ISSUER = "https://console.redhat.com/api/idm"
ISSUER = "idm/v1"
AUD_REGISTER_HOST = "register host"
AUD_REGISTER_DOMAIN = "register domain"
CLAIM_ORG_ID = "org"
CLAIM_DOMAIN_ID = "domid"
CLAIM_FDQN = "fdqn"
CLAIM_INVENTORY_ID = "invid"

CHECKED_HOST_CLAIMS = {
    ## JWT registered claims
    # issuer (StringOrURI)
    "iss": ISSUER,
    # subject StringOrURI, will be set to cert subject CN
    "sub": None,
    # audience (array of StringOrURI), our value must match one entry
    "aud": AUD_REGISTER_HOST,
    # date: expires, not before, issued at (automatically set)
    "exp": None,
    "nbf": None,
    "iat": None,
    # claim identifier (uuid string), automatically set
    "jti": None,
    ## private claims
    # cert subject org (O) (string)
    CLAIM_ORG_ID: None,
    # host-based inventory id (uuid string)
    CLAIM_INVENTORY_ID: None,
    # client's fqdn (str)
    CLAIM_FDQN: None,
    # domain_id (uuid string)
    CLAIM_DOMAIN_ID: None,
}  # type: typing.Dict[str, typing.Union[str, int, typing.List[str], None]]

CHECKED_DOMAIN_CLAIMS = {
    ## JWT registered claims
    # issuer (StringOrURI)
    "iss": ISSUER,
    # subject StringOrURI, will be set to user id
    "sub": None,
    # audience (array of StringOrURI), our value must match one entry
    "aud": AUD_REGISTER_HOST,
    # date: expires, not before, issued at (automatically set)
    "exp": None,
    # "nbf": None,
    # "iat": None,
    # claim identifier (uuid string), automatically set
    "jti": None,
    ## private claims
    # user's organization id
    CLAIM_ORG_ID: None,
}  # type: typing.Dict[str, typing.Union[str, int, typing.List[str], None]]

JWKDict: jwk.JWK

if hasattr(jwk.JWK, "get"):
    # modern JWK implementation with dict interface
    class JWKDict(jwk.JWK):  # type: ignore
        def _public_params(self):
            """Export all parameters except private key values

            The original implementation only exports known public attributes.
            """
            d = {}
            d.update(self)
            # pop private key members (if set)
            reg = jwk.JWKValuesRegistry[d["kty"]]
            for name, param in reg.items():
                if not param.public:
                    d.pop(name, None)
            return d

        def export(self, private_key=True, as_dict=False):
            raise NotImplementedError

else:
    # (ignore no-redef warning)
    class JWKDict(jwk.JWK):  # type: ignore
        """A forward-compatible JWK subclass with dict interface

        The JWK implementation of jwcrypto <= 0.8 (RHEL 8, 9) does not have
        a dict-like interface and its export functions do not support
        `as_dict` argument.
        """

        if typing.TYPE_CHECKING:
            _params: typing.Dict[str, typing.Any]
            _key: typing.Dict[str, typing.Any]
            _unknown: typing.Dict[str, typing.Any]

        def _get_dict(self, key: str) -> dict:
            if key in jwk.JWKParamsRegistry:
                return self._params
            elif key in jwk.JWKValuesRegistry[self._params["kty"]]:
                return self._key
            else:
                return self._unknown

        def __setitem__(self, key: str, value: typing.Any) -> None:
            dct = self._get_dict(key)
            dct[key] = value

        def __getitem__(self, key: str) -> typing.Any:
            dct = self._get_dict(key)
            return dct[key]

        def get(self, key, default=None):
            try:
                return self[key]
            except KeyError:
                return default

        def __contains__(self, key: str) -> bool:
            try:
                self[key]
            except KeyError:
                return False
            else:
                return True

        def __iter__(self):
            for key in self._params:
                yield key
            for key in self._key:
                yield key
            for key in self._unknown:
                yield key

        def export(self, private_key=True, as_dict=False):
            raise NotImplementedError

        def export_public(self, as_dict=False):
            """Exports the public key in the standard JSON format."""
            if not self.has_public:
                raise jwk.InvalidJWKType("No public key available")
            pub = self._public_params()
            if as_dict:
                return pub
            return json_encode(pub)

        def export_private(self, as_dict=False):
            """Export the private key in the standard JSON format."""
            if not self.has_private:
                raise jwk.InvalidJWKType("No private key available")
            return self._export_all(as_dict)

        def _export_all(self, as_dict=False):
            d = {}
            d.update(self._params)
            d.update(self._key)
            d.update(self._unknown)
            if as_dict:
                return d
            return json_encode(d)

        def _public_params(self):
            """Export all parameters except private key values

            The original implementation only exports known public attributes.
            """
            d = self._export_all(as_dict=True)
            # pop private key members (if set)
            reg = jwk.JWKValuesRegistry[d["kty"]]
            for name, param in reg.items():
                if not param.public:
                    d.pop(name, None)
            return d


class MultiJWST(jwt.JWT):
    """Extended JWT that supports multiple signatures

    Technically RFC 7519 conform JWTs must be in compact notation and can
    only have a signature. This implementation can create non-standard
    signed token (JWS token) with multiple signatures. Verification
    ensures that at least one key from a JWKSet can be verified.
    """

    if typing.TYPE_CHECKING:
        claims: typing.Dict[str, typing.Any]
        header: typing.Dict[str, typing.Any]

    def make_signed_token(
        self, key: typing.Union[JWKDict, jwk.JWKSet]
    ) -> None:
        """Signs the payload."""
        t = jws.JWS(self.claims)
        if self._algs:
            t.allowed_algs = self._algs

        if isinstance(key, JWKDict):
            t.add_signature(key, protected=self.header)
        else:
            for k in key:
                try:
                    header = self.header.copy()
                except (KeyError, ValueError):
                    header = {}
                header["alg"] = k["alg"]
                header["kid"] = k["kid"]
                t.add_signature(k, protected=header)

        self.token = t

    def deserialize_json(
        self,
        tok: typing.Union[dict, str],
        key=typing.Union[jwk.JWK, jwk.JWKSet],
    ):
        """Deserialize a JWT JSON token."""
        if isinstance(tok, str):
            tok_dict = json_decode(tok)
            tok_str = tok
        elif isinstance(tok, dict):
            tok_dict = tok
            tok_str = json_encode(tok)
        else:
            raise TypeError(f"tok must be a dict or str, got {type(tok)}.")
        # see RFC 7516, section 9
        if "payload" in tok_dict:
            self.token = jws.JWS()
        elif "ciphertext" in tok_dict:
            # ipahcc does not use JWE
            raise NotImplementedError("JWE support is not implemented")
        else:
            raise ValueError(f"Token format unrecognized: {tok}")

        # Apply algs restrictions if any, before performing any operation
        if self._algs:
            self.token.allowed_algs = self._algs

        self.deserializelog = []
        # now deserialize and also decrypt/verify (or raise) if we
        # have a key
        success_key = None
        if key is None:
            self.token.deserialize(tok_str, None)
        elif isinstance(key, JWKDict):
            self.token.deserialize(tok_str, key)
            success_key = key
            self.deserializelog.append("Success")
        elif isinstance(key, jwk.JWKSet):
            self.token.deserialize(tok, None)
            if "kid" in self.token.jose_header:
                # single-signature / compact JWT
                keyid = self.token.jose_header["kid"]
                kid_key = key.get_key(keyid)
                if not kid_key:
                    raise jwt.JWTMissingKey(f"Key ID {keyid} not in key set")
                self.token.deserialize(tok, kid_key)
                success_key = kid_key
            else:
                for k in key:
                    try:
                        self.token.deserialize(tok, k)
                        self.deserializelog.append("Success")
                        success_key = k
                        break
                    except Exception as e:  # pylint: disable=broad-except
                        self.deserializelog.append(
                            "Key [%s] failed: [%s]" % (k["kid"], repr(e))
                        )
                        continue
                if "Success" not in self.deserializelog:
                    raise jwt.JWTMissingKey("No working key found in key set")
        else:
            raise ValueError("Unrecognized Key Type")

        if success_key is not None:
            kid = success_key.get("kid")
            if isinstance(self.token.jose_header, list):
                # multi-signature JWTs have a list of header
                # pick header that matches our key
                for hdr in self.token.jose_header:
                    if hdr["kid"] == kid:
                        self.header = hdr
                        break
                else:
                    raise ValueError(
                        f"jose_header is missing entry for {kid}."
                    )
            else:
                self.header = self.token.jose_header
            self.claims = self.token.payload.decode("utf-8")
            self._check_provided_claims()


class InvalidKey(JWException):
    def __init__(
        self,
        key: JWKDict,
        name: str,
        msg: str,
    ):
        super().__init__(msg)
        self.key = key
        self.name = name
        self.msg = msg


class InvalidToken(JWException):
    pass


def load_key(raw_key: typing.Union[str, dict]) -> JWKDict:
    """Load JWK from serialized JSON string

    Supports both public and private keys.
    """
    if isinstance(raw_key, str):
        dct = json_decode(raw_key)  # type: dict
        key = JWKDict(**dct)
    elif isinstance(raw_key, dict):
        key = JWKDict(**raw_key)
    else:
        raise TypeError(type(raw_key))

    kid = key.get("kid")
    if not kid:
        raise InvalidKey(key, "kid", "Missing key identifier (kid)")

    if key["kty"] != KTY:
        raise InvalidKey(key, "kty", "Unsupported key type.")
    if key["kty"] == "EC" and key["crv"] not in CRV_TO_ALG:
        raise InvalidKey(key, "crv", "Unsupported EC curve.")

    # jwcrypto ensure consistency between use and key_ops
    if "use" in key:
        if key["use"] != "sig":
            raise InvalidKey(key, "use", "Invalid key usage, expected 'sig'.")
    elif "key_ops" in key:
        if "verify" not in key["key_ops"]:
            raise InvalidKey(
                key,
                "key_ops",
                "Key is not valid for 'verify'.",
            )
    else:
        raise InvalidKey(key, "use", "Either 'use' or 'key_ops' must be set.")

    # exp is not standardized in RFC 7517, but commonly used
    if "exp" not in key:
        raise InvalidKey(key, "exp", "Key expiration 'exp' is missing.")
    if time.time() > key["exp"]:
        raise InvalidKey(key, "exp", "key is expired")

    return key


def get_token_kid(raw_token: str) -> typing.Dict[str, str]:
    """Parse and return key identifer from protected headers

    The function also performs some basic sanity check, but it does not
    perform any verification!
    """
    t = jwt.JWT()
    t.deserializes(raw_token)
    if not isinstance(t, jws.JWS):
        raise InvalidToken("Token is not a signed token.")
    header = t.token.jose_header
    alg = header.get("alg")
    if alg not in SUPPORTED_ALGS:
        raise InvalidToken("Unsupported algorithm.")
    kid = header.get("kid")
    if kid:
        raise InvalidToken("Token is missing kid.")
    return kid


def validate_host_token(
    raw_token: str,
    pub_key: JWKDict,
    cert_o: str,
    cert_cn: str,
    inventory_id: str,
    fqdn: str,
    domain_id: str,
    validity: int = 10 * 60,
    leeway: int = 60,
) -> typing.Tuple[dict, dict]:
    if isinstance(pub_key, JWKDict):
        assert not pub_key.has_private
    else:
        assert all(not k.has_private for k in pub_key)
    # str values must be equal, "aud" must match one element
    # "exp" and "nbf" are validated using current time, validity and leeway
    # other None values are checked for presence (e.g. "idm_inventory_id")
    check_claims = CHECKED_HOST_CLAIMS.copy()
    check_claims.update(
        {
            "sub": cert_cn,
            CLAIM_ORG_ID: cert_o,
            CLAIM_INVENTORY_ID: inventory_id,
            CLAIM_FDQN: fqdn,
            CLAIM_DOMAIN_ID: domain_id,
        }
    )

    t = MultiJWST(check_claims=check_claims)
    t.validity = validity
    t.leeway = leeway
    if raw_token.startswith("{"):
        t.deserialize_json(raw_token, pub_key)
    else:
        t.deserialize(raw_token, pub_key)
    return json_decode(t.header), json_decode(t.claims)


def generate_private_key(
    crv="P-256", kid=None, *, validity: int = 90 * 86400
) -> JWKDict:
    """Generate EC key (for testing purposes only)

    Returns (private_key, public_key) as serialized strings.
    """
    priv = JWKDict(
        generate="EC",
        crv=crv,
        use="sig",
        alg=CRV_TO_ALG[crv],
        exp=int(time.time() + validity),
    )
    if kid is None:
        # truncated thumbprint of public key
        # RFC 7517, 8.1.1, recommends up to 8 chars
        kid = priv.thumbprint()[:8]
    priv["kid"] = kid
    return priv


def get_public_key(priv_key: JWKDict) -> JWKDict:
    pub_key = priv_key.export_public(as_dict=True)
    return JWKDict(**pub_key)


def generate_host_token(
    key: typing.Union[JWKDict, jwk.JWKSet],
    cert_o: str,
    cert_cn: str,
    inventory_id: str,
    fqdn: str,
    domain_id: str,
    validity: int = 10 * 60,
) -> jwt.JWT:
    """Generate a signed token (for testing purposes only)"""
    if isinstance(key, JWKDict):
        assert key.has_private
        assert key["kty"] == "EC"
        header = {"kid": key["kid"], "alg": CRV_TO_ALG[key["crv"]]}
    else:
        assert all(k.has_private for k in key)
        assert all(k["kty"] == "EC" for k in key)
        header = {}
    default_claims = CHECKED_HOST_CLAIMS.copy()
    # aud should be an array
    default_claims["aud"] = [AUD_REGISTER_HOST]

    t = MultiJWST(header=header, default_claims=default_claims)
    t.validity = validity
    t.claims = {
        "sub": cert_cn,
        CLAIM_ORG_ID: cert_o,
        CLAIM_INVENTORY_ID: inventory_id,
        CLAIM_FDQN: fqdn,
        CLAIM_DOMAIN_ID: domain_id,
        # use 6 random bytes -> 8 characters as random id
        # Our tokens are valid for mere hours, 48 random bits are sufficient.
        "jti": base64.urlsafe_b64encode(os.urandom(6)).decode("ascii"),
    }
    t.make_signed_token(key)
    return t


def generate_domain_token(
    key: JWKDict,
    user_id: str,
    user_org: str,
    validity: int = 2 * 60 * 60,
) -> jwt.JWT:
    """Generate a signed token (for testing purposes only)"""
    assert key.has_private
    assert key["kty"] == "EC"
    header = {"kid": key["kid"], "alg": CRV_TO_ALG[key["crv"]]}
    default_claims = CHECKED_DOMAIN_CLAIMS.copy()
    # aud should be an array
    default_claims["aud"] = [AUD_REGISTER_DOMAIN]

    t = MultiJWST(header=header, default_claims=default_claims)
    t.validity = validity
    t.claims = {
        "sub": user_id,
        CLAIM_ORG_ID: user_org,
        # use 9 random bytes -> 12 characters as random id
        "jti": base64.urlsafe_b64encode(os.urandom(9)).decode("ascii"),
    }
    t.make_signed_token(key)
    return t


def test():
    CLIENT_RHSM_ID = "1ee437bc-7b65-40cc-8a02-c24c8a7f9368"
    CLIENT_INVENTORY_ID = "1efd5f0e-7589-44ac-a9af-85ba5569d5c3"
    CLIENT_FQDN = "client.ipa-hcc.test"
    ORG_ID = "16765486"
    DOMAIN_ID = "772e9618-d0f8-4bf8-bfed-d2831f63c619"

    # server part
    priv_key1 = generate_private_key()
    print(priv_key1)  # noqa: T201
    priv_key2 = generate_private_key()
    print(priv_key2)  # noqa: T201

    tok = generate_host_token(
        priv_key1,
        cert_o=ORG_ID,
        cert_cn=CLIENT_RHSM_ID,
        inventory_id=CLIENT_INVENTORY_ID,
        fqdn=CLIENT_FQDN,
        domain_id=DOMAIN_ID,
    )
    raw_tok = tok.serialize(compact=False)

    # registration agent part
    pub_key1 = load_key(get_public_key(priv_key1))
    pub_key2 = load_key(get_public_key(priv_key2))
    pub_jwks = jwk.JWKSet()
    pub_jwks.add(pub_key1)
    pub_jwks.add(pub_key2)

    header, claims = validate_host_token(
        raw_tok,
        pub_key1,
        cert_o=ORG_ID,
        cert_cn=CLIENT_RHSM_ID,
        inventory_id=CLIENT_INVENTORY_ID,
        fqdn=CLIENT_FQDN,
        domain_id=DOMAIN_ID,
    )
    print(claims)  # noqa: T201
    validate_host_token(
        raw_tok,
        pub_jwks,
        cert_o=ORG_ID,
        cert_cn=CLIENT_RHSM_ID,
        inventory_id=CLIENT_INVENTORY_ID,
        fqdn=CLIENT_FQDN,
        domain_id=DOMAIN_ID,
    )

    try:
        validate_host_token(
            raw_tok,
            pub_key1,
            cert_o=ORG_ID,
            cert_cn=CLIENT_RHSM_ID,
            inventory_id=CLIENT_INVENTORY_ID,
            fqdn="other fqdn",
            domain_id=DOMAIN_ID,
        )
    except JWException as e:
        print("Expected error:", e)  # noqa: T201

    priv_jwks = jwk.JWKSet()
    priv_jwks.add(priv_key1)
    priv_jwks.add(priv_key2)
    tok = generate_host_token(
        priv_jwks,
        ORG_ID,
        CLIENT_RHSM_ID,
        inventory_id=CLIENT_INVENTORY_ID,
        fqdn=CLIENT_FQDN,
        domain_id=DOMAIN_ID,
    )
    raw_tok = tok.serialize(compact=False)
    print(raw_tok)  # noqa: T201

    pub_jwks = jwk.JWKSet()
    # pub_jwks.add(pub_key1)
    pub_jwks.add(pub_key2)
    header, claims = validate_host_token(
        raw_tok,
        pub_jwks,
        cert_o=ORG_ID,
        cert_cn=CLIENT_RHSM_ID,
        inventory_id=CLIENT_INVENTORY_ID,
        fqdn=CLIENT_FQDN,
        domain_id=DOMAIN_ID,
    )
    print(header)  # noqa: T201
    print(claims)  # noqa: T201

    tok = generate_domain_token(priv_key1, "12345", ORG_ID)
    toc_string = tok.serialize(compact=False)
    print("domain token:", toc_string)  # noqa: T201
    # short_claim = {
    #    k: v
    #    for k, v in json_decode(tok.claims).items()
    #    if k in {"sub", "exp", "o", "jti"}
    # }
    # sig = toc_string.split(".")[-1]
    # print(short_claim)  # noqa: T201
    # print(base64url_encode(json_encode(short_claim)) + "." + sig)  # noqa: T201


if __name__ == "__main__":
    test()
