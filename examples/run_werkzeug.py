# -*- coding: utf-8 -*-

from werkzeug.serving import run_simple
from sina import Sina
from sina.config import DEFAULT_CONFIG


if __name__ == '__main__':
    DEFAULT_CONFIG['chunked'] = True
    app = Sina(DEFAULT_CONFIG)
    run_simple('0.0.0.0', 8000, app)
