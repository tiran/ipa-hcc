from __future__ import absolute_import

import argparse
import logging
import signal
import threading

# Use dasbus from Anaconda Installer instead?
# https://pypi.org/project/dasbus/
import dbus
import dbus.exceptions
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

import ipalib
from ipaplatform.paths import paths

from ipahcc import hccplatform
from ipahcc.server.hccapi import HCCAPI, APIError, DEFAULT_TIMEOUT

try:
    from systemd import daemon as sd
except ImportError:
    sd = None

if hccplatform.PY2:
    # pylint: disable=import-error
    from Queue import PriorityQueue
else:
    from queue import PriorityQueue  # pylint: disable=import-error

hccconfig = hccplatform.HCCConfig()
logger = logging.getLogger("ipa-hcc-dbus")


parser = argparse.ArgumentParser(
    "ipa-hcc-dbus", "IPA Hybrid Cloud Console D-Bus service"
)
parser.add_argument(
    "--debug",
    "-d",
    help="Enable debug logging",
    dest="debug",
    action="store_true",
)
parser.add_argument(
    "--timeout",
    help="Timeout for HTTP and LDAP requests",
    dest="timeout",
    default=DEFAULT_TIMEOUT,
    type=int,
)

# status_code (q: int)
# reason (s: str)
# url (s: str)
# headers (a{ss} dict[str, str])
# JSON body (s: str)
# exit_code (q: int)
# error_message (s: str)
DBUS_RETURN = "qssa{ss}sqs"


class LookupQueue(object):
    priorities = {
        "stop": -1,
        "register_domain": 30,
        "update_domain": 50,
        "check_host": 100,
    }

    def __init__(self, timeout=DEFAULT_TIMEOUT, maxsize=0):
        self._queue = PriorityQueue(maxsize=maxsize)
        ipalib.api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        ipalib.api.finalize()
        self._hccapi = HCCAPI(ipalib.api, timeout=timeout)

    def _response_to_dbus(self, response, exit_code=0, exit_message="OK"):
        """Convert requests.Response to D-Bus return value"""
        return (
            response.status_code,
            response.reason,
            response.url,
            response.headers,
            response.text,
            exit_code,
            exit_message,
        )

    def stop(self):
        self._queue.put((self.priorities["stop"], None, None, None, None))

    def add_task(self, name, args, ok_cb, err_cb):
        prio = self.priorities[name]
        method = getattr(self._hccapi, name)
        argcount = method.__func__.__code__.co_argcount
        if len(args) != argcount - 1:
            raise ValueError(args, argcount)
        self._queue.put((prio, name, args, ok_cb, err_cb))

    def run(self):
        while True:
            prio, name, args, ok_cb, err_cb = self._queue.get(block=True)
            if prio == -1:
                logger.info("Stopping lookup queue")
                break
            try:
                with self._hccapi as hccapi:
                    method = getattr(hccapi, name)
                    _info, response = method(*args)
                ok_cb(*self._response_to_dbus(response))
            except APIError as e:
                logger.exception("API call failed: %s %r", method, args)
                # err_cb can only return exception name + string, use ok_cb()
                # to return structured information.
                ok_cb(*e.to_dbus())
            except BaseException as e:  # pylint: disable=broad-except
                logger.exception("Unexpected error: %s %r", method, args)
                err_cb(e)

            self._queue.task_done()


class IPAHCCDbus(dbus.service.Object):
    """IPA HCC D-Bus service

    All methods have a common return type:
        int: HTTP error code
        str: reason
        str: url
        Dict[str, str]: headers dict
        str: response content as UTF-8 string (typically JSON payload)
        int: exit code
        str: exit message
    """

    def __init__(
        self, conn, object_path, bus_name, loop, timeout=DEFAULT_TIMEOUT
    ):
        super(IPAHCCDbus, self).__init__(conn, object_path, bus_name)
        self.loop = loop
        self._lq = LookupQueue(timeout)
        self._lq_thread = threading.Thread(target=self._lq.run)
        self._lq_thread.start()

    @dbus.service.method(
        hccplatform.HCC_DBUS_IFACE_NAME,
        "ssss",
        DBUS_RETURN,
        async_callbacks=("ok_cb", "err_cb"),
    )
    def check_host(
        self, domain_id, inventory_id, rhsm_id, fqdn, ok_cb, err_cb
    ):
        """Check host by RHSM uuid"""
        args = (
            domain_id,
            inventory_id,
            rhsm_id,
            fqdn,
        )
        self._lq.add_task("check_host", args, ok_cb, err_cb)

    @dbus.service.method(
        hccplatform.HCC_DBUS_IFACE_NAME,
        "ss",
        DBUS_RETURN,
        async_callbacks=("ok_cb", "err_cb"),
    )
    def register_domain(self, domain_id, token, ok_cb, err_cb):
        """Register a new domain"""
        args = domain_id, token
        self._lq.add_task("register_domain", args, ok_cb, err_cb)

    @dbus.service.method(
        hccplatform.HCC_DBUS_IFACE_NAME,
        "b",
        DBUS_RETURN,
        async_callbacks=("ok_cb", "err_cb"),
    )
    def update_domain(self, update_server_only, ok_cb, err_cb):
        """Register a new domain"""
        args = (update_server_only,)
        self._lq.add_task("update_domain", args, ok_cb, err_cb)

    @dbus.service.signal(hccplatform.HCC_DBUS_IFACE_NAME)
    def stop(self):
        self.signal_handler(signal.SIGTERM, None)

    def signal_handler(self, sig, stack):  # pylint: disable=unused-argument
        self._lq.stop()
        self._lq_thread.join()
        self.loop.quit()


def main(args=None):
    args = parser.parse_args(args)

    logging.basicConfig(
        format="%(message)s",
        level=logging.DEBUG if args.debug else logging.INFO,
    )
    if hccconfig.environment != "prod":
        logger.warning("Using environment '%s'", hccconfig.environment)

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    dbus.mainloop.glib.threads_init()

    bus = dbus.SystemBus()
    bus_name = dbus.service.BusName(hccplatform.HCC_DBUS_NAME, bus)
    mainloop = GLib.MainLoop()
    obj = IPAHCCDbus(
        bus,
        hccplatform.HCC_DBUS_OBJ_PATH,
        bus_name,
        mainloop,
        timeout=args.timeout,
    )
    signal.signal(signal.SIGINT, obj.signal_handler)
    signal.signal(signal.SIGTERM, obj.signal_handler)
    # notify systemd service
    if sd is not None and sd.booted():
        sd.notify("READY=1")

    mainloop.run()


if __name__ == "__main__":
    main()
