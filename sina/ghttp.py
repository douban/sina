# -*- coding: utf-8 -*-

import re
import time
import os
import select
import gzip
import StringIO
from os import access
from os.path import join, exists, getmtime, getsize
from urllib import unquote
from BaseHTTPServer import BaseHTTPRequestHandler as _

from .git import Git


def format_date_time(timestamp):
    year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)
    return "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
        _.weekdayname[wd], day, _.monthname[month], year, hh, mm, ss
    )


def callback(p):
    ofd = p.stdout.fileno()
    efd = p.stderr.fileno()
    p.stdin.flush()
    timeout = 5
    while timeout:
        r_ready, w_ready, x_ready = select.select([ofd, efd], [], [], 1)
        timeout -= 1

        if ofd in r_ready:
            data = os.read(ofd, 8192)
            if not data:
                break
            timeout += 1
            yield data

        if efd in r_ready:
            data = os.read(efd, 8192)
            yield data
            break

    output, err = p.communicate()
    if output:
        yield output
        if err:
            yield err


class GHTTPServer(object):

    VALID_SERVICE_TYPES = ['upload-pack', 'receive-pack']

    SERVICES = [
        ["POST", 'service_rpc',      re.compile("(.*?)/git-upload-pack$"),  'upload-pack'],
        ["POST", 'service_rpc',      re.compile("(.*?)/git-receive-pack$"), 'receive-pack'],

        ["GET",  'get_info_refs',    re.compile("(.*?)/info/refs$")],
        ["GET",  'get_text_file',    re.compile("(.*?)/HEAD$")],
        ["GET",  'get_text_file',    re.compile("(.*?)/objects/info/alternates$")],
        ["GET",  'get_text_file',    re.compile("(.*?)/objects/info/http-alternates$")],
        ["GET",  'get_info_packs',   re.compile("(.*?)/objects/info/packs$")],
        ["GET",  'get_text_file',    re.compile("(.*?)/objects/info/[^/]*$")],
        ["GET",  'get_loose_object', re.compile("(.*?)/objects/[0-9a-f]{2}/[0-9a-f]{38}$")],
        ["GET",  'get_pack_file',    re.compile("(.*?)/objects/pack/pack-[0-9a-f]{40}\\.pack$")],
        ["GET",  'get_idx_file',     re.compile("(.*?)/objects/pack/pack-[0-9a-f]{40}\\.idx$")],
    ]

    def __init__(self, config=None):
        self.set_config(config)
        self.git = Git(self.config.get('git_path'))

    def set_config(self, config):
        self.config = config or {}

    def set_config_setting(self, key, value):
        self.config[key] = value

    def __call__(self, environ, start_response):
        if hasattr(self, '_before_request_handler'):
            self._before_request_handler(environ)
        request = Request(environ=environ)
        body = self.call(request)
        start_response(request.status, request.headers.items())
        if hasattr(self, '_after_request_handler'):
            self._after_request_handler(environ)
        return body

    def call(self, request):
        match = self.match_routing(request.environ["PATH_INFO"].lstrip('/'),
                                   request.environ["REQUEST_METHOD"])
        if not match:
            return self.render_not_found(request)
        cmd, path, reqfile, rpc = match
        request.rpc = rpc
        request.reqfile = reqfile
        if cmd == "not_allowed":
            return self.render_method_not_allowed(request)

        if hasattr(self, '_has_permission_handler'):
            need_perm = self.get_permission(cmd, rpc, request.environ['QUERY_STRING'])
            has_perm = self._has_permission_handler(request.environ, path, need_perm)
            if not has_perm:
                return self.render_no_access(request)

        if hasattr(self, '_get_repo_path_handler'):
            request.dir = self._get_repo_path_handler(request.environ, path)
        else:
            request.dir = self.get_git_dir(path)

        if not request.dir:
            return self.render_not_found(request)
        func = getattr(self, cmd)
        return func(request)

    def service_rpc(self, request):
        if not self.has_access(request, True):
            return self.render_no_access(request)
        input = self.read_body(request)
        rpc = request.rpc
        git_cmd = "upload_pack" if rpc == "upload-pack" else "receive_pack"
        request.status = "200 OK"
        request.headers["Content-Type"] = "application/x-git-%s-result" % rpc
        env = request.environ.get('env')
        return getattr(self.git, git_cmd)(request.dir, {"msg": input, "env": env}, callback)

    def get_info_refs(self, request):
        service_name = self.get_service_type(request.environ["QUERY_STRING"])
        request.rpc = service_name
        if self.has_access(request):
            git_cmd = "upload_pack" if service_name == "upload-pack" else "receive_pack"
            refs = getattr(self.git, git_cmd)(request.dir, {"advertise_refs": True})
            request.status = "200 OK"
            request.headers["Content-Type"] = "application/x-git-%s-advertisement" % service_name
            self.hdr_nocache(request)

            def read_file():
                yield self.pkt_write("# service=git-%s\n" % service_name)
                yield self.pkt_flush
                yield refs
            return read_file()
        else:
            return self.dumb_info_refs(request)

    def get_text_file(self, request):
        return self.send_file(request, "text/plain")

    def dumb_info_refs(self, request):
        self.update_server_info(request.dir)
        return self.send_file(request, "text/plain; charset=utf-8")

    def get_info_packs(self, request):
        # objects/info/packs
        return self.send_file(request, "text/plain; charset=utf-8")

    def get_loose_object(self, request):
        return self.send_file(request, "application/x-git-loose-object", cached=True)

    def get_pack_file(self, request):
        return self.send_file(request, "application/x-git-packed-objects", cached=True)

    def get_idx_file(self, request):
        return self.send_file(request, "application/x-git-packed-objects-toc", cached=True)

    def get_service_type(self, query_string):
        def get_param():
            for query in query_string.split('&'):
                param = tuple(query.split('='))
                if param and param[0] == "service":
                    return param[1]
        service_type = get_param()
        if not service_type:
            return False
        if service_type[0:4] != 'git-':
            return False
        return service_type.replace('git-', '')

    @classmethod
    def match_routing(cls, path_info, request_method):
        for service in cls.SERVICES:
            rpc = None
            if len(service) == 4:
                method, handler, re_match, rpc = service
            elif len(service) == 3:
                method, handler, re_match = service
            m = re_match.match(path_info)
            if m:
                if method != request_method:
                    return ["not_allowed", None, None, None]
                cmd = handler
                path = m.group(1)
                file = path_info.replace(path + '/', '')
                return [cmd, path, file, rpc]
        return None

    def send_file(self, request, content_type, cached=False):
        reqfile = join(request.dir, request.reqfile)
        if not self.is_subpath(reqfile, request.dir):
            return self.render_no_access(request)
        if not exists(reqfile) or not access(reqfile, os.R_OK):
            return self.render_not_found(request)

        request.status = "200 OK"
        request.headers["Content-Type"] = content_type
        request.headers["Last-Modified"] = format_date_time(getmtime(reqfile))

        if cached:
            self.hdr_cache_forever(request)
        else:
            self.hdr_nocache(request)

        size = getsize(reqfile)
        if size:
            request.headers["Content-Length"] = size

            def read_file():
                with open(reqfile, "rb") as f:
                    while True:
                        part = f.read(8192)
                        if not part:
                            break
                        yield part
            return read_file()
        else:
            with open(reqfile, "rb") as f:
                part = f.read()
                request.headers["Content-Length"] = str(len(part))
            return [part]

    def update_server_info(self, path):
        self.git.update_server_info(path)

    def read_chunked_body(self, request):
        # wsgiref with no chunked support
        environ = request.environ
        input = environ.get('wsgi.input')
        length = environ.get('CONTENT_LENGTH', '0')
        length = 0 if length == '' else int(length)
        body = ''
        if length == 0:
            if input is None:
                return
            if environ.get('HTTP_TRANSFER_ENCODING', '0') == 'chunked':
                size = int(input.readline(), 16)
                while size > 0:
                    body += input.read(size)
                    input.read(2)
                    size = int(input.readline(), 16)
        else:
            body = input.read(length)
        return body

    def read_body(self, request):
        if self.config.get('chunked'):
            return self.read_chunked_body(request)
        env = request.environ
        input = env.get('wsgi.input')
        if env.get('HTTP_CONTENT_ENCODING') == 'gzip':
            compressedstream = StringIO.StringIO(input.read())
            gzipper = gzip.GzipFile(fileobj=compressedstream)
            return gzipper.read()
        return input.read()

    # ------------------------------
    # packet-line handling functions
    # ------------------------------

    @property
    def pkt_flush(self):
        return '0000'

    def pkt_write(self, str):
        # TODO: use zfill
        PKT_FORMAT = "{0:{fill}{align}{width}{base}}{1}"
        return PKT_FORMAT.format(len(str) + 4,
                                 str,
                                 base='x',
                                 width=4,
                                 fill='0',
                                 align='>')

    # ------------------------
    # header writing functions
    # ------------------------

    def hdr_nocache(self, request):
        request.headers["Expires"] = "Fri, 01 Jan 1980 00:00:00 GMT"
        request.headers["Pragma"] = "no-cache"
        request.headers["Cache-Control"] = "no-cache, max-age=0, must-revalidate"

    def hdr_cache_forever(self, request):
        now = int(time.time())
        request.headers["Date"] = str(now)
        request.headers["Expires"] = str(now + 31536000)
        request.headers["Cache-Control"] = "public, max-age=31536000"

    # --------------------------------------
    # HTTP error response handling functions
    # --------------------------------------

    def render_method_not_allowed(self, request):
        env = request.environ
        if env["SERVER_PROTOCOL"] == "HTTP/1.1":
            request.status = "405 Method not allowed"
            request.headers["Content-Type"] = "text/plain"
            return ["Method Not Allowed"]
        else:
            request.status = "400 Bad Request"
            request.headers["Content-Type"] = "text/plain"
            return ["Bad Request"]

    def render_not_found(self, request):
        request.status = "404 Not Found"
        request.headers["Content-Type"] = "text/plain"
        return ["Not Found"]

    def render_no_access(self, request):
        request.status = "403 Forbidden"
        request.headers["Content-Type"] = "text/plain"
        return ["Forbidden"]

    def has_access(self, request, check_content_type=False):
        rpc = request.rpc
        env = request.environ
        if check_content_type:
            if env["CONTENT_TYPE"] != "application/x-git-%s-request" % rpc:
                return False
        if rpc not in self.VALID_SERVICE_TYPES:
            return False
        if rpc == 'receive-pack':
            if "receive_pack" in self.config:
                return self.config.get("receive_pack")
        if rpc == 'upload-pack':
            if "upload_pack" in self.config:
                return self.config.get("upload_pack")
        return self.get_config_setting(request.dir, rpc)

    def get_config_setting(self, path, service_name):
        service_name = service_name.replace('-', '')
        setting = self.git.get_config_setting(path,
                                              "http.%s" % service_name)
        if service_name == 'uploadpack':
            return setting != 'false'
        else:
            return setting == 'true'

    def get_git_dir(self, path):
        root = self.get_project_root()
        path = join(root, path)
        if not self.is_subpath(path, root):
            return False
        if self.is_git_dir(path):
            return path
        return False

    def is_git_dir(self, d):
        """ This is taken from the git setup.c:is_git_directory. """
        isdir = os.path.isdir
        join = os.path.join
        isfile = os.path.isfile
        islink = os.path.islink
        if isdir(d) and (isdir(join(d, 'objects')) and
                isdir(join(d, 'refs'))):
            headref = join(d, 'HEAD')
            return isfile(headref) or (
                     islink(headref) and
                     os.readlink(headref).startswith('refs'))
        return False

    def get_project_root(self):
        root = self.config.get("project_root") or os.getcwd()
        return root

    def is_subpath(self, path, checkpath):
        path = unquote(path)
        checkpath = unquote(checkpath)
        # Remove trailing slashes from filepath
        checkpath = checkpath.replace("\/+$", '')
        if re.match("^%s(\/|$)" % checkpath, path):
            return True

    # decorator hook

    # args: environ
    def before_request(self, f):
        self._before_request_handler = f
        return f

    # args: environ
    def after_request(self, f):
        self._after_request_handler = f
        return f

    # args: environ, path
    def get_repo_path(self, f):
        self._get_repo_path_handler = f
        return f

    # args: environ, path, perm
    def has_permission(self, f):
        self._has_permission_handler = f
        return f

    def get_permission(self, cmd, rpc, query):
        if cmd == 'get_info_refs':
            rpc = self.get_service_type(query)
        if rpc == 'receive-pack':
            return 'write'
        return 'read'


class Request(object):

    def __init__(self, headers=None, environ=None):
        self.headers = {} if not headers else headers
        self.environ = {} if not environ else environ
        self.reqfile = None
        self.rpc = None
        self.status = None
        self.dir = None
