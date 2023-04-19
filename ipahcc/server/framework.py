#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2023  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""Simple WSGI framework
"""
import collections
import inspect
import json
import logging
import re
import traceback

from ipahcc import hccplatform
from ipahcc.server.schema import validate_schema, ValidationError
from ipahcc.server.util import parse_rhsm_cert

# pylint: disable=import-error
if hccplatform.PY2:
    from httplib import responses as http_responses
else:
    from http.client import responses as http_responses
# pylint: enable=import-error

logger = logging.getLogger(__name__)


class HTTPException(Exception):
    def __init__(self, code, msg):
        super(HTTPException, self).__init__(code, msg)
        self.code = code
        self.message = msg


_Route = collections.namedtuple("_Route", "method path schema")


def route(method, path, schema=None):
    """Decorator to mark a method as HTTP request handler"""
    if method not in {"GET", "POST", "PUT", "PATCH"}:
        raise ValueError(method)
    if not path.startswith("^") or not path.endswith("$"):
        raise ValueError(path)

    def inner(func):
        func.wsgi_route = _Route(method, path, schema)
        return func

    return inner


class JSONWSGIApp(object):
    """Trivial, opinionated WSGI framework for REST-like JSON API

    - supports request methods GET, POST, PUT, PATCH.
    - POST, PUT, PATCH requests must be "application/json".
    - responses are always "application/json", even for errors.
    - handlers support optional schema validation for request and response
      payload.

    Example::

       @route("POST", "^/example/(?P<id>[^/]+)$", schema=None)
       def example(self, env, body, id):
           return {"id": id}
    """

    max_content_length = 10240

    def __init__(self, api=None):
        if api is None:  # pragma: no cover
            import ipalib  # pylint: disable=import-outside-toplevel

            self.api = ipalib.api
        else:
            self.api = api
        if not self.api.isdone("bootstrap"):
            self.api.bootstrap(in_server=False)
        self.routes = (
            self._get_routes()
        )  # type: dict[re.compile, tuple[str, callable]]

    def _get_routes(self):
        """Inspect class and get a list of routes"""
        routes = {}
        for name, meth in inspect.getmembers(self, inspect.ismethod):
            if name.startswith("_"):
                continue
            wr = getattr(meth, "wsgi_route", None)
            if wr:
                methmap = routes.setdefault(wr.path, {})
                methmap[wr.method] = (meth, wr.schema)

        return [
            (re.compile(path), methmap)
            for path, methmap in sorted(routes.items())
        ]

    def _route_lookup(self, env):
        """Lookup route by path info

        Returns callable, schema, body, kwargs

        Raises:
          - 411 length required
          - 413 request too large
          - 405 method not allowed
          - 406 unsupported content type
          - 404 not found
        """
        method = env["REQUEST_METHOD"]
        pathinfo = env["PATH_INFO"]

        if method in {"POST", "PUT", "PATCH"}:
            # limit content-length to prevent DoS
            try:
                length = int(env["CONTENT_LENGTH"])
            except (KeyError, ValueError):
                length = -1
            if length < 0:
                raise HTTPException(411, "Length required.")
            if length > self.max_content_length:
                raise HTTPException(413, "Request entity too large.")
            # POST/PUT/PATCH must be content-type application/json
            content_type = env["CONTENT_TYPE"]
            if content_type != "application/json":
                raise HTTPException(
                    406,
                    "Unsupported content type {content_type}.".format(
                        content_type=content_type
                    ),
                )
            body = json.loads(env["wsgi.input"].read(length))
        else:
            body = None

        for pathre, methmap in self.routes:
            mo = pathre.match(pathinfo)
            if mo is None:
                continue
            meth, schema = methmap.get(method, (None, None))
            if meth is None:
                raise HTTPException(
                    405,
                    "Method {method} not allowed.".format(method=method),
                )
            return meth, schema, body, mo.groupdict()

        raise HTTPException(
            404, "{pathinfo} not found".format(pathinfo=pathinfo)
        )

    def _validate_schema(self, instance, schema_name, suffix):
        """Validate JSON schema"""
        schema_id = "/schemas/{schema_name}/{suffix}".format(
            schema_name=schema_name, suffix=suffix
        )
        try:
            validate_schema(instance, schema_id)
        except ValidationError:
            logger.exception("schema violation")
            raise HTTPException(
                400,
                "schema violation: invalid JSON for {schema_id}".format(
                    schema_id=schema_id,
                ),
            )

    def before_call(self):
        """Before handle method call hook"""

    def after_call(self):
        """After handle method call hook"""

    def parse_cert(self, env):
        """Parse XRHID certificate"""

        cert_pem = env.get("SSL_CLIENT_CERT")
        if not cert_pem:
            raise HTTPException(412, "SSL_CLIENT_CERT is missing or empty.")
        try:
            return parse_rhsm_cert(cert_pem)
        except ValueError as e:
            raise HTTPException(400, str(e))

    def __call__(self, env, start_response):
        try:
            meth, schema_name, body, kwargs = self._route_lookup(env)
            if schema_name is not None:
                self._validate_schema(body, schema_name, "request")

            self.before_call()
            try:
                result = meth(env, body, **kwargs)
            finally:
                self.after_call()

            if schema_name is not None:
                self._validate_schema(result, schema_name, "response")

            response = json.dumps(result)
            code = 200
        except BaseException as e:  # pylint: disable=broad-except
            if isinstance(e, HTTPException):
                code = e.code
                title = http_responses[code]
                details = e.message
                logger.info("%i: %s", code, details)
            else:
                logger.exception("Request failed")
                code = 500
                title = "server error: {e}".format(e=e)
                details = traceback.format_exc()
            response = json.dumps(
                {"status": code, "title": title, "details": details}
            )

        if isinstance(response, hccplatform.text):
            response = response.encode("utf-8")

        status_line = "{} {}".format(code, http_responses[code])
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(response)),
        }
        headers.update(hccplatform.HTTP_HEADERS)

        start_response(status_line, list(headers.items()))
        return [response]
