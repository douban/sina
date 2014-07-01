# -*- coding: utf-8 -*-

from wsgiref.simple_server import make_server
from sina import Sina
from sina.config import DEFAULT_CONFIG


if __name__ == '__main__':
    DEFAULT_CONFIG['chunked'] = True
    app = Sina(DEFAULT_CONFIG)
    server = make_server('0.0.0.0', 8000, app)
    server.serve_forever()
