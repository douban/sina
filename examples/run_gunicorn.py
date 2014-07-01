# -*- coding: utf-8 -*-
try:
    import subprocess
    from gevent import monkey
    subprocess.Popen = monkey.get_original('subprocess', 'Popen')
except:
    pass

from sina import Sina
from sina.config import DEFAULT_CONFIG

app = Sina(DEFAULT_CONFIG)

# gunicorn run_gunicorn:app -b 0.0.0.0:8000 -k gevent
# gunicorn run_gunicorn:app -b 0.0.0.0:8000
