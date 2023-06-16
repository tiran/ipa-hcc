import json
import logging
import typing

import dbus
import dbus.mainloop.glib

from ipahcc import hccplatform

from .hccapi import APIError, APIResult

__all__ = ("register_domain", "update_domain")

logger = logging.getLogger("dbus-client")


# map some error identifiers to human-readable messages
# https://gitlab.freedesktop.org/dbus/dbus/-/blob/4a1f6a0c2ce6d10eefb110696019c144db632618/dbus/dbus-protocol.h#L354
DBUS_ERRORS = {
    "org.freedesktop.DBus.Error.ServiceUnknown": (
        f"Service '{hccplatform.HCC_DBUS_SERVICE}' is not running (service unknown)."
    ),
    "org.freedesktop.DBus.Error.NameHasNoOwner": (
        f"Service '{hccplatform.HCC_DBUS_SERVICE}' is not running (name has no owner)."
    ),
    "org.freedesktop.DBus.Error.AccessDenied": (
        f"Access denied to '{hccplatform.HCC_DBUS_SERVICE}'."
    ),
}  # type: dict[str, str]


class DBusError(Exception):
    """Custom DBusException variant with friendly message"""

    def __init__(self, name: typing.Optional[str], message: str):
        self._name = name
        self._message = message
        if name:
            self._friendly_message = DBUS_ERRORS.get(name)
        else:
            self._friendly_message = None
        super().__init__(name, message)

    def __str__(self) -> str:
        if self._friendly_message:
            return self._friendly_message
        elif self._name:
            return f"{self._name}: {self._message}"
        else:
            return self._message

    def get_dbus_message(self) -> str:
        return self._message

    def get_dbus_name(self) -> typing.Optional[str]:
        return self._name


def _dbus_getmethod(
    method_name: str, bus: typing.Optional[dbus.Bus] = None
) -> typing.Callable:  # pragma: no cover
    """Get method wrapper from HCC D-Bus service"""
    if bus is None:
        bus = dbus.SystemBus()
    obj = bus.get_object(
        hccplatform.HCC_DBUS_NAME, hccplatform.HCC_DBUS_OBJ_PATH
    )
    iface = dbus.Interface(obj, hccplatform.HCC_DBUS_IFACE_NAME)
    return getattr(iface, method_name)


def _dbus_call(method_name: str, *args, **kwargs) -> APIResult:
    logger.info(
        "D-Bus call: %s%s (name: %s, path: %s)",
        method_name,
        args,
        hccplatform.HCC_DBUS_NAME,
        hccplatform.HCC_DBUS_OBJ_PATH,
    )
    try:
        method = _dbus_getmethod(method_name, kwargs.get("bus"))
        result = method(*args)
    except dbus.exceptions.DBusException as e:
        logger.info(
            "Call to '%s' failed with an internal error: %s",
            hccplatform.HCC_DBUS_NAME,
            e,
        )
        logger.debug("D-Bus exception", exc_info=True)
        raise DBusError(e.get_dbus_name(), e.get_dbus_message()) from None

    # convert from D-Bus types to Python types
    tmp = APIResult(*result)
    rid = str(tmp.id)
    status_code = int(tmp.status_code)
    reason = str(tmp.reason)
    url = str(tmp.url) if tmp.url else None
    assert tmp.headers
    headers = {str(k).lower(): str(v) for k, v in tmp.headers.items()}
    if headers.get("content-type") == "application/json":
        assert isinstance(tmp.body, str)
        body = json.loads(tmp.body)
    else:
        body = str(tmp.body)
    exit_code = int(tmp.exit_code)
    exit_message = str(tmp.exit_message)

    result = APIResult(
        rid, status_code, reason, url, headers, body, exit_code, exit_message
    )
    if result.exit_code == 0:
        return result
    else:
        raise APIError(result)


def register_domain(
    domain_id: str, token: str, bus: typing.Optional[dbus.Bus] = None
) -> APIResult:
    return _dbus_call("register_domain", domain_id, token, bus=bus)


def update_domain(
    update_server_only: bool = False, bus: typing.Optional[dbus.Bus] = None
) -> APIResult:
    return _dbus_call("update_domain", update_server_only, bus=bus)


def status_check(bus: typing.Optional[dbus.Bus] = None) -> APIResult:
    return _dbus_call("status_check", bus=bus)
