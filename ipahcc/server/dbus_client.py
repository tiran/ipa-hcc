import json
import logging

import dbus
import dbus.mainloop.glib

from ipahcc import hccplatform
from .hccapi import APIError, APIResult

__all__ = ("init", "check_host", "register_domain", "update_domain")

logger = logging.getLogger("dbus-client")


def init():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    dbus.mainloop.glib.threads_init()


def _dbus_call(method_name, *args, **kwargs):
    bus = kwargs.get("bus")
    if bus is None:
        bus = dbus.SystemBus()
    try:
        obj = bus.get_object(
            hccplatform.HCC_DBUS_NAME, hccplatform.HCC_DBUS_OBJ_PATH
        )
        iface = dbus.Interface(obj, hccplatform.HCC_DBUS_IFACE_NAME)
        result = getattr(iface, method_name)(*args)
    except dbus.exceptions.DBusException:
        logger.exception(
            "D-Bus service %s failed with an internal error",
            hccplatform.HCC_DBUS_NAME,
        )
        raise

    # convert from D-Bus types to Python types
    tmp = APIResult(*result)
    status_code = int(tmp.status_code)
    reason = str(tmp.reason)
    url = str(tmp.url) if tmp.url else None
    headers = {str(k).lower(): str(v) for k, v in tmp.headers.items()}
    if headers.get("content-type") == "application/json":
        body = json.loads(tmp.body)
    else:
        body = str(tmp.body)
    exit_code = int(tmp.exit_code)
    exit_message = str(tmp.exit_message)

    result = APIResult(
        status_code, reason, url, headers, body, exit_code, exit_message
    )
    if result.exit_code == 0:
        return result
    else:
        raise APIError(result)


def check_host(domain_id, inventory_id, rhsm_id, fqdn, bus=None):
    return _dbus_call(
        "check_host", domain_id, inventory_id, rhsm_id, fqdn, bus=bus
    )


def register_domain(domain_id, token, bus=None):
    return _dbus_call("register_domain", domain_id, token, bus=bus)


def update_domain(update_server_only=False, bus=None):
    return _dbus_call("update_domain", update_server_only, bus=bus)
