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
import typing
from http.client import responses as http_responses

from ipahcc import hccplatform
from ipahcc.server.hccapi import APIResult
from ipahcc.server.schema import ValidationError, validate_schema
from ipahcc.server.util import parse_rhsm_cert

logger = logging.getLogger(__name__)


class HTTPException(Exception):
    def __init__(self, code, msg):
        super().__init__(code, msg)
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


class JSONWSGIApp:
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
        self.routes = self._get_routes()

    def _get_routes(self) -> typing.List[typing.Tuple["re.Pattern", dict]]:
        """Inspect class and get a list of routes"""
        routes: typing.Dict[str, dict] = {}
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

    def _route_lookup(
        self, env: dict
    ) -> typing.Tuple[
        typing.Callable,
        typing.Optional[str],
        typing.Dict[str, typing.Any],
        typing.Dict[str, str],
    ]:
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
                    f"Unsupported content type {content_type}.",
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
                    f"Method {method} not allowed.",
                )
            return meth, schema, body, mo.groupdict()

        raise HTTPException(404, f"{pathinfo} not found")

    def _validate_schema(
        self,
        instance: dict,
        schema_name: str,
        suffix: str = "",
    ) -> None:
        """Validate JSON schema"""
        schema_id = f"{schema_name}{suffix}"
        try:
            validate_schema(instance, schema_id)
        except ValidationError:
            logger.exception("schema violation")
            raise HTTPException(
                400,
                f"schema violation: invalid JSON for {schema_id}",
            ) from None

    def before_call(self) -> None:
        """Before handle method call hook"""

    def after_call(self) -> None:
        """After handle method call hook"""

    def parse_cert(self, env: dict) -> typing.Tuple[str, str]:
        """Parse XRHID certificate"""

        cert_pem = env.get("SSL_CLIENT_CERT")
        if not cert_pem:
            raise HTTPException(412, "SSL_CLIENT_CERT is missing or empty.")
        try:
            return parse_rhsm_cert(cert_pem)
        except ValueError as e:
            raise HTTPException(400, str(e)) from None

    def __call__(
        self, env: dict, start_response: typing.Callable
    ) -> typing.Iterable[typing.ByteString]:
        try:
            meth, schema_name, body, kwargs = self._route_lookup(env)
            if schema_name is not None:
                self._validate_schema(body, schema_name, "Request")

            self.before_call()
            try:
                result = meth(env, body, **kwargs)
            finally:
                self.after_call()

            if schema_name is not None:
                self._validate_schema(result, schema_name, "Response")

            response = json.dumps(result)
            status = 200
        except BaseException as e:  # pylint: disable=broad-except
            error_id = APIResult.genrid()
            if isinstance(e, HTTPException):
                status = e.code
                title = http_responses[status]
                details = e.message
                logger.info("%i: %s", status, details)
            else:
                logger.exception("Request failed")
                status = 500
                title = f"server error: {e}"
                details = traceback.format_exc()
            logger.error("[%s] %i %s", error_id, status, title)
            errors = {
                "errors": [
                    {
                        "id": error_id,
                        "status": str(status),
                        "title": title,
                        "detail": details,
                    }
                ]
            }
            self._validate_schema(errors, "Errors")
            response = json.dumps(errors)

        status_line = f"{status} {http_responses[status]}"
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(response)),
        }
        headers.update(hccplatform.HTTP_HEADERS)

        start_response(status_line, list(headers.items()))
        return [response.encode("utf-8")]
