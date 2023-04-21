__all__ = ("application",)

# import WSGI app before api
from ipalib import api

from ipahcc.registration.wsgi import Application

application = Application(api=api)
