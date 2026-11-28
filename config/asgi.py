import os
import sys

path = os.path.expanduser('~/Multiplex64')
if path not in sys.path:
    sys.path.append(path)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

from django.core.asgi import get_asgi_application

application = get_asgi_application()