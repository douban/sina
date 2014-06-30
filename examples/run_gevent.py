# -*- coding: utf-8 -*-

try:
    from gevent.monkey import patch_all
    patch_all(subprocess=False, aggressive=False)
    from gevent.pywsgi import WSGIServer
except ImportError:
    print 'You need install gevent manually! System shutdown.'

from sina import Sina
from sina.config import DEFAULT_CONFIG


if __name__ == '__main__':
    app = Sina(DEFAULT_CONFIG)
    server = WSGIServer(('0.0.0.0', 8000), app)
    server.serve_forever()
