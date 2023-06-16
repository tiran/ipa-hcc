import argparse
import logging
import queue
import signal
import threading
import typing

# Use dasbus from Anaconda Installer instead?
# https://pypi.org/project/dasbus/
import dbus
import dbus.exceptions
import dbus.mainloop.glib
import dbus.service
import ipalib
from gi.repository import GLib
from ipaplatform.paths import paths

from ipahcc import hccplatform
from ipahcc.server.hccapi import DEFAULT_TIMEOUT, HCCAPI, APIError

try:
    from systemd import daemon as sd
except ImportError:
    sd = None  # type: ignore


logger = logging.getLogger("ipa-hcc-dbus")


parser = argparse.ArgumentParser(
    "ipa-hcc-dbus", "IPA Hybrid Cloud Console D-Bus service"
)
parser.add_argument(
    "--verbose",
    "-v",
    help="Enable verbose logging",
    dest="verbose",
    default=0,
    action="count",
)
parser.add_argument(
    "--version",
    "-V",
    help="Show version number and exit",
    action="version",
    version=f"ipa-hcc {hccplatform.VERSION} (IPA {hccplatform.IPA_VERSION})",
)
parser.add_argument(
    "--timeout",
    help="Timeout for HTTP and LDAP requests",
    dest="timeout",
    default=DEFAULT_TIMEOUT,
    type=int,
)

# id (s: str)
# status_code (q: int)
# reason (s: str)
# url (s: str)
# headers (a{ss} dict[str, str])
# JSON body (s: str)
# exit_code (q: int)
# error_message (s: str)
DBUS_RETURN = "sqssa{ss}sqs"


class LookupQueue:
    priorities = {
        "stop": -1,
        "register_domain": 30,
        "update_domain": 50,
        "status_check": 60,
    }

    def __init__(self, hccapi: HCCAPI, maxsize: int = 0):
        self._queue: queue.Queue = queue.PriorityQueue(maxsize=maxsize)
        self._hccapi: HCCAPI = hccapi

    def stop(self):
        self._queue.put((self.priorities["stop"], None, None, None, None))

    def add_task(
        self,
        name: str,
        args: tuple,
        ok_cb: typing.Callable,
        err_cb: typing.Callable,
    ):
        prio = self.priorities[name]
        method = getattr(self._hccapi, name)
        argcount = method.__func__.__code__.co_argcount
        if len(args) != argcount - 1:  # pragma: no cover
            raise ValueError(args, argcount)
        logger.info("Queue %s%s", name, args)
        self._queue.put((prio, name, args, ok_cb, err_cb))

    def run(self):
        while True:
            prio, name, args, ok_cb, err_cb = self._queue.get(block=True)
            if prio == -1:
                logger.info("Stopping lookup queue")
                self._queue.task_done()
                break
            try:
                logger.info("API call %s%s", name, args)
                with self._hccapi as hccapi:
                    method = getattr(hccapi, name)
                    _info, result = method(*args)
                logger.info("Result: %r", result)
                ok_cb(*result.to_dbus())
            except APIError as e:
                logger.exception("API call failed: %s %r", method, args)
                # err_cb can only return exception name + string, use ok_cb()
                # to return structured information.
                ok_cb(*e.to_dbus())
            except BaseException as e:  # pylint: disable=broad-except
                logger.exception("Unexpected error: %s %r", method, args)
                err_cb(e)
            finally:
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
        self,
        conn: dbus.Bus,
        object_path: str,
        bus_name: str,
        loop,
        hccapi: HCCAPI,
    ) -> None:
        super().__init__(conn, object_path, bus_name)
        self.loop = loop
        self._lq = LookupQueue(hccapi)
        self._lq_thread = threading.Thread(target=self._lq.run)
        self._lq_thread.start()

    # python-dbus on RHEL 8 is incompatible with type annotations
    # dbus.decorators.decorator() uses inspect.getargspec(), which fails with
    # ValueError: Function has keyword-only parameters or annotations, use
    #     getfullargspec() API which can support them
    @dbus.service.method(
        hccplatform.HCC_DBUS_IFACE_NAME,
        "ss",
        DBUS_RETURN,
        async_callbacks=("ok_cb", "err_cb"),
    )
    def register_domain(self, domain_id, token, ok_cb, err_cb):
        """Register a new domain"""
        args = (str(domain_id), str(token))
        self._lq.add_task("register_domain", args, ok_cb, err_cb)

    @dbus.service.method(
        hccplatform.HCC_DBUS_IFACE_NAME,
        "b",
        DBUS_RETURN,
        async_callbacks=("ok_cb", "err_cb"),
    )
    def update_domain(self, update_server_only, ok_cb, err_cb):
        """Register a new domain"""
        args = (bool(update_server_only),)
        self._lq.add_task("update_domain", args, ok_cb, err_cb)

    @dbus.service.method(
        hccplatform.HCC_DBUS_IFACE_NAME,
        "",
        DBUS_RETURN,
        async_callbacks=("ok_cb", "err_cb"),
    )
    def status_check(self, ok_cb, err_cb):
        """Get status information"""
        args = ()
        self._lq.add_task("status_check", args, ok_cb, err_cb)

    @dbus.service.signal(hccplatform.HCC_DBUS_IFACE_NAME)
    def stop(self):
        self.signal_handler(signal.SIGTERM, None)

    def signal_handler(  # pylint: disable=unused-argument
        self, sig: int, stack
    ) -> None:
        self._lq.stop()
        self._lq_thread.join()
        self.loop.quit()


def main(args=None):  # pragma: no cover
    args = parser.parse_args(args)

    logging.basicConfig(
        format="%(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    dbus.mainloop.glib.threads_init()

    ipalib.api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
    ipalib.api.finalize()
    hccapi = HCCAPI(ipalib.api, args.timeout)

    bus = dbus.SystemBus()
    bus_name = dbus.service.BusName(hccplatform.HCC_DBUS_NAME, bus)
    mainloop = GLib.MainLoop()
    obj = IPAHCCDbus(
        bus,
        hccplatform.HCC_DBUS_OBJ_PATH,
        bus_name,
        loop=mainloop,
        hccapi=hccapi,
    )
    signal.signal(signal.SIGINT, obj.signal_handler)
    signal.signal(signal.SIGTERM, obj.signal_handler)
    # notify systemd service
    if sd is not None and sd.booted():
        sd.notify("READY=1")

    mainloop.run()


if __name__ == "__main__":
    main()
