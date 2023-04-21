__all__ = ("application",)

# import WSGI app before api
from ipalib import api

from ipahcc.mockapi.wsgi import Application

application = Application(api=api)
