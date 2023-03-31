__all__ = ("application",)

# import WSGI app before api
from ipahcc.mockapi.wsgi import Application
from ipalib import api

application = Application(api=api)
