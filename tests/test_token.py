import unittest

from jwcrypto import jwk, jwt
from jwcrypto.common import json_decode

import conftest
from ipahcc.server import token


class TestToken(unittest.TestCase):
    def generate_token(
        self,
        key,
        cert_o=conftest.ORG_ID,
        cert_cn=conftest.CLIENT_RHSM_ID,
        inventory_id=conftest.CLIENT_INVENTORY_ID,
        fqdn=conftest.CLIENT_FQDN,
        domain_id=conftest.DOMAIN_ID,
        **kwargs,
    ):
        return token.generate_host_token(
            key, cert_o, cert_cn, inventory_id, fqdn, domain_id, **kwargs
        )

    def validate_token(
        self,
        tok,
        key,
        cert_o=conftest.ORG_ID,
        cert_cn=conftest.CLIENT_RHSM_ID,
        inventory_id=conftest.CLIENT_INVENTORY_ID,
        fqdn=conftest.CLIENT_FQDN,
        domain_id=conftest.DOMAIN_ID,
        **kwargs,
    ):
        return token.validate_host_token(
            tok,
            key,
            cert_o=cert_o,
            cert_cn=cert_cn,
            inventory_id=inventory_id,
            fqdn=fqdn,
            domain_id=domain_id,
            **kwargs,
        )

    def test_jwk(self):
        priv = token.generate_private_key()
        self.assertTrue(priv.has_private)
        self.assertIsInstance(priv, token.JWKDict)
        pub = token.get_public_key(priv)
        self.assertFalse(pub.has_private)
        self.assertIsInstance(pub, token.JWKDict)

        raw_priv = priv.export_private()
        self.assertIsInstance(raw_priv, str)
        raw_pub = pub.export_public()
        self.assertIsInstance(raw_pub, str)

        priv2 = token.load_key(raw_priv)
        pub2 = token.load_key(raw_pub)

        exp = priv["exp"]
        self.assertIsInstance(exp, int)
        kid = priv["kid"]
        self.assertIsInstance(kid, str)

        for key in (priv, pub, priv2, pub2):
            self.assertIsInstance(key, jwk.JWK)
            self.assertTrue(priv.has_public)
            self.assertEqual(key["kid"], kid)
            self.assertEqual(key["exp"], exp)
            self.assertEqual(key["crv"], "P-256")
            self.assertEqual(key["alg"], "ES256")
            if key.has_private:
                self.assertIn("d", key)
            else:
                self.assertNotIn("d", key)

    def test_jwt_single_sig(self):
        # compact JWT with single signature
        priv1 = token.generate_private_key()
        pub1 = token.get_public_key(priv1)
        tok = self.generate_token(priv1)
        self.assertIsInstance(tok, jwt.JWT)
        self.assertIsInstance(tok, token.MultiJWST)

        compact = tok.serialize()
        self.assertIsInstance(compact, str)
        self.assertEqual(compact.count("."), 2)
        j = tok.serialize(compact=False)
        self.assertIsInstance(j, str)
        self.assertIsInstance(json_decode(j), dict)

        self.validate_token(compact, pub1)
        self.validate_token(j, pub1)

        pub_set = jwk.JWKSet()
        pub_set.add(pub1)
        self.validate_token(compact, pub_set)
        self.validate_token(j, pub_set)

    def test_jwt_multi_sig(self):
        priv1 = token.generate_private_key()
        pub1 = token.get_public_key(priv1)
        priv2 = token.generate_private_key()
        pub2 = token.get_public_key(priv2)

        priv_set = jwk.JWKSet()
        priv_set.add(priv1)
        priv_set.add(priv2)

        pub_set = jwk.JWKSet()
        pub_set.add(pub1)
        pub_set.add(pub2)

        tok = self.generate_token(priv_set)
        j = tok.serialize(compact=False)

        self.validate_token(j, pub1)
        self.validate_token(j, pub2)
        self.validate_token(j, pub_set)

    # TODO: test failure cases
