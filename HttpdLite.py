#!/usr/bin/python
#
# httpd_lite.py, Copyright 2012, Bjarni R. Einarsson <http://bre.klaki.net/>
#
# A very light-weight boilerplate HTTP daemon.
#
################################################################################
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the  GNU  Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful,  but  WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see: <http://www.gnu.org/licenses/>
#
################################################################################
#
import cgi
import hashlib
import hmac
import os
import socket
import tempfile
import threading
import time
import traceback
import urllib
from urlparse import urlparse
try:
  from urlparse import parse_qs
except ImportError:
  from cgi import parse_qs

import Cookie
import SocketServer
from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler

try:
  import json
  if hasattr(json, 'JsonReader'):
    def json_decode(data):           return json.JsonReader().read(data)
    def json_encode(data, indent=0): return json.JsonWriter().write(data)
  else:
    def json_decode(data):           return json.loads(data, indent=indent)
    def json_encode(data, indent=0): return json.dumps(data, indent=indent)
except:
  def json_decode(data):           raise ImportError("Failed to import json")
  def json_encode(data, indent=0): raise ImportError("Failed to import json")


def GuessMimeType(path):
  if '.' in os.path.basename(path):
    if path.endswith('.gz'):
      try:
        ext = '.'.join(path.split('.')[-2:]).lower()
      except IndexError:
        ext = path.split('.')[-1].lower()
    else:
      ext = path.split('.')[-1].lower()
    if ext in ('jpg', 'jpeg'):
      return 'image/jpeg'
    elif ext in ('png', 'gif'):
      return 'image/%s' % ext
    elif ext in ('htm', 'html', 'html.gz', 'htm.gz'):
      return 'text/html'
    elif ext in ('css', 'css.gz'):
      return 'text/css'
    elif ext in ('js', 'js.gz'):
      return 'text/javascript'
    elif ext in ('json', 'json.gz'):
      return 'application/json'
    elif ext.split('.')[0] in ('c', 'cfg', 'conf', 'cpp', 'csv',
                               'h', 'hpp', 'log', 'md', 'me',
                               'py', 'rb', 'rc', 'txt'):
      return 'text/plain'
    else:
      return 'application/octet-stream'
  return 'text/plain'


class RequestHandler(SimpleXMLRPCRequestHandler):

  rpc_paths = ( )

  def setup(self):
    self.pending_headers = [ ]
    self.chunked = self.suppress_body = False
    SimpleXMLRPCRequestHandler.setup(self)

  def send_header(self, header, value):
    self.wfile.write('%s: %s\r\n' % (header, value))

  def end_headers(self):
    self.wfile.write('\r\n')

  def address_string(self):
    addr = self.header('X-Forwarded-For')
    proto = self.header('X-Forwarded-Proto')
    lasthop = SimpleXMLRPCRequestHandler.address_string(self)
    if addr:
      if addr.startswith('::ffff:'):
        addr = addr[7:]
      if proto == 'https':
        return '%s/ssl/%s' % (addr, lasthop)
      else:
        return '/'.join([addr, lasthop])
    else:
      return lasthop

  def setCookie(self, name, value,
                path='/', maxAge=None, httpOnly=False, secure=False,
                delete=False):
    if delete:
      value, maxAge = '', 0
    self.pending_headers.append(('Set-Cookie', ''.join([
      '%s=%s' % (name, value),
      '; Path=%s' % path,
      (maxAge is not None) and ('; Max-Age=%s' % maxAge) or '',
      (httpOnly and '; HttpOnly' or ''),
      (secure and '; Secure' or '')
    ])))

  def absolute_url(self):
    return '%s://%s%s' % (self.header('X-Forwarded-Proto', 'http'),
                          self.header('Host', 'localhost'),
                          self.path)

  def sendStdHdrs(self, header_list=[], cachectrl='private',
                                        mimetype='text/html'):
    if not mimetype:
      mimetype = 'application/octet-stream'
    if mimetype.startswith('text/') and ';' not in mimetype:
      mimetype += '; charset=utf-8'
    for cookie in self.pending_headers:
      self.send_header(*cookie)
    self.send_header('Cache-Control', cachectrl)
    self.send_header('Content-Type', mimetype)
    for header in header_list:
      self.send_header(header[0], header[1])
    self.end_headers()

  def sendChunk(self, chunk):
    if self.chunked:
      self.wfile.write('%x\r\n' % len(chunk))
      self.wfile.write(chunk)
      self.wfile.write('\r\n')
    else:
      self.wfile.write(chunk)

  def sendEof(self):
    if self.chunked and not self.suppress_body: self.wfile.write('0\r\n\r\n')

  def sendResponse(self, message, code=200, msg='OK', mimetype='text/html',
                         header_list=[], chunked=False, length=None,
                         cachectrl='private'):
    self.server.logger.log_request(self, code, message and len(message) or '-')
    self.wfile.write('HTTP/1.1 %s %s\r\n' % (code, msg))
    if code == 401:
      self.send_header('WWW-Authenticate',
                       'Basic realm=PK%d' % (time.time()/3600))

    self.chunked = chunked
    if chunked:
      self.send_header('Transfer-Encoding', 'chunked')
    else:
      if length:
        self.send_header('Content-Length', length)
      elif not chunked:
        self.send_header('Content-Length', len(message or ''))

    self.sendStdHdrs(header_list=header_list,
                     mimetype=mimetype,
                     cachectrl=cachectrl)
    if message and not self.suppress_body:
      self.sendChunk(message)

  def sendRedirect(self, url, header_list=None):
    headers = (header_list or [])[:]
    headers.append(('Location', url))
    return self.sendResponse('<h1><a href="%s">Moved here</a></h1>\n' % url,
                             code=302, msg='Moved', cachectrl='no-cache',
                             header_list=headers)

  def do_HEAD(self):
    self.suppress_body = True
    self.do_GET(command='HEAD')

  def do_GET(self, command='GET'):
    (scheme, netloc, path, params, query, frag) = urlparse(self.path)
    qs = parse_qs(query)
    self.post_data = None
    self.command = command
    try:
      if 'cookie' in self.headers:
        cookies = Cookie.SimpleCookie(self.headers['cookie'])
      else:
        cookies = {}
      return self.handleHttpRequest(scheme, netloc, path, params, query, frag,
                                    qs, None, cookies)
    except socket.error:
      pass
    except:
      print '%s' % traceback.format_exc()
      self.sendResponse('<h1>Internal Error</h1>\n', code=500, msg='Error')

  def do_PUT(self):
    self.do_POST(command='PUT')

  def do_DELETE(self):
    self.do_POST(command='DELETE')

  def header(self, name, default=None):
    return self.headers.get(name) or self.headers.get(name.lower()) or default

  def do_POST(self, command='POST'):
    (scheme, netloc, path, params, query, frag) = urlparse(self.path)
    qs = parse_qs(query)

    self.command = command
    self.post_data = tempfile.TemporaryFile()
    self.old_rfile = self.rfile
    try:
      # First, buffer the POST data to a file...
      clength = cleft = int(self.header('Content-Length'))
      while cleft > 0:
        rbytes = min(64*1024, cleft)
        self.post_data.write(self.rfile.read(rbytes))
        cleft -= rbytes

      # Juggle things so the buffering is invisble.
      self.post_data.seek(0)
      self.rfile = self.post_data

      ctype, pdict = cgi.parse_header(self.header('Content-Type', ''))
      if ctype == 'multipart/form-data':
        self.post_data.seek(0)
        posted = cgi.parse_multipart(self.rfile, pdict)

      elif ctype == 'application/x-www-form-urlencoded':
        if clength >= 50*1024*1024:
          raise Exception(("Refusing to parse giant posted query "
                           "string (%s bytes).") % clength)
        posted = cgi.parse_qs(self.rfile.read(clength), 1)

      elif command == 'POST':
        # We wrap the XMLRPC request handler in _BEGIN/_END in order to
        # expose the request environment to the RPC functions.
        rci = self.server.xmlrpc
        return rci._END(SimpleXMLRPCRequestHandler.do_POST(rci._BEGIN(self)))

      else:
        posted = {}
        posted[command.upper()] = self.rfile.read(clength)

      self.post_data.seek(0)
    except:
      print '%s' % traceback.format_exc()
      self.sendResponse('<h1>Internal Error</h1>\n', code=500, msg='Error')
      self.rfile = self.old_rfile
      self.post_data = None
      return

    try:
      if 'cookie' in self.headers:
        cookies = Cookie.SimpleCookie(self.headers['cookie'])
      else:
        cookies = {}
      return self.handleHttpRequest(scheme, netloc, path, params, query, frag,
                                    qs, posted, cookies)
    except socket.error:
      pass
    except:
      print '%s' % traceback.format_exc()
      self.sendResponse('<h1>Internal Error</h1>\n', code=500, msg='Error')

    self.rfile = self.old_rfile
    self.post_data = None

  def handleHttpRequest(self, scheme, netloc, path,
                              params, query, frag, qs, posted, cookies):
    auth_handler = self.server.auth_handler
    if auth_handler:
      self.auth_info = None
      rv = auth_handler.authHttpRequest(self, path, qs, posted, cookies)
      if rv is not None:
        return rv
    return self.server.boss.handleHttpRequest(self, scheme, netloc, path,
                                              params, query, frag,
                                              qs, posted, cookies)


class AuthHandler:
  """Base class for handling OAuth-type authentication flows."""

  def __init__(self):
    self.twitter = {
      'key': '',
      'callback': None
    }
    self.google = {
      'name': 'Google',
      'auth_url': 'https://accounts.google.com/o/oauth2/auth?response_type=code&scope=https://www.googleapis.com/auth/userinfo.profile&',
      'token_url': 'https://www.googleapis.com/oauth2/v1/tokeninfo?',
      'profile_url': 'https://www.googleapis.com/oauth2/v1/userinfo?access_token=',
      'client_id': '',
      'client_secret': ''
    }
    self.facebook = {
      'name': 'Facebook',
      'auth_url': 'https://graph.facebook.com/oauth/authorize?',
      'token_url': 'https://graph.facebook.com/oauth/access_token?',
      'graph_url': 'https://graph.facebook.com/me?',
      'client_id': '',
      'client_secret': ''
    }
    self.oauth2 = {
      'google': self.google,
      'facebook': self.facebook
    }

  def authHttpRequest(self, req, path, qs, posted, cookies):
    if not path.startswith('/_authlite/'):
      return None

    for provider in self.oauth2:
      if path.startswith('/_authlite/'+provider):
        oauth2 = self.oauth2[provider]
        if oauth2['client_id']:
          return self.doOauth2(oauth2, req, path, qs, posted, cookies)

    if self.twitter['key']:
      if path.startswith('/_authlite/twitter_login'):
        return self.handleTwitterLogin(req, path, qs, posted, cookies)

    return None

  def doOauth2(self, oauth2, req, path, qs, posted, cookies):
    code = qs.get('code', [None])[0]
    state = qs.get('state', [''])[0]
    args = {
      'client_id': oauth2['client_id'], 
      'redirect_uri': req.absolute_url(),
      'state': state
    }
    if code:
      args.update({
        'client_secret': oauth2['client_secret'],
        'code': code,
      })
      token_url = oauth2['token_url'] + urllib.urlencode(args)
      response = cgi.parse_qs(urllib.urlopen(token_url).read())
      req.auth_info = (oauth2['name'], response['access_token'][-1])
      return None
    else:
      return req.sendRedirect(oauth2['auth_url'] + urllib.urlencode(args))

  def getFacebookProfile(self, access_token):
    args = {'access_token': access_token}
    graph_url = self.facebook['graph_url'] + urllib.urlencode(args)
    return json_decode(urllib.urlopen(graph_url).read())

  def handleTwitterLogin(self, req, path, qs, posted, cookies):
    pass


class XmlRpcInterface:
  """Base class for handling XML-RPC methods."""

  def __init__(self, boss):
    self.lock = threading.Lock()
    self.request = None
    self.boss = boss

  def _BEGIN(self, request_object):
    self.lock.acquire()
    self.request = request_object
    return request_object

  def _END(self, rv=None):
    if self.request:
      self.request = None
      self.lock.release()
    return rv


class Boss:
  """Stub boss class."""

  def handleHttpRequest(self, request_handler,
                              scheme, netloc, path, params, query, frag,
                              qs, posted, cookies):
    if request_handler.auth_info:
      request_handler.sendResponse(('<h1>Welcome!</h1><p>%s</p>'
                                    ) % (request_handler.auth_info, ),
                                   cachectrl='no-cache')
    else:
      request_handler.sendResponse("""
<h1>Hello world</h1>
<p><a href='/_authlite/facebook'>Log in with Facebook?</a></p>
<p><a href='/_authlite/google'>Log in with Google?</a></p>
                                   """, cachectrl='no-cache')


class Logger:
  """Stub logger class."""

  def log_message(self, request_handler, message):
    if request_handler:
      return request_handler.log_message(message)
    print '*** %s' % message

  def log_request(self, request_handler, code, message):
    return request_handler.log_request(code, message)


class Server(SocketServer.ThreadingMixIn, SimpleXMLRPCServer):
  """Basic HTTP daemon class."""

  def __init__(self, sspec, boss,
               handler=RequestHandler,
               logger=Logger,
               xmlrpc=None,
               auth_handler=None):
    SimpleXMLRPCServer.__init__(self, sspec, handler)
    self.boss = boss
    self.handler = handler
    self.auth_handler = auth_handler
    self.logger = logger()
    if xmlrpc:
      self.xmlrpc = xmlrpc(boss)
      self.register_introspection_functions()
      self.register_instance(self.xmlrpc)
    else:
      self.xmlrpc = None

  def finish_request(self, request, client_address):
   try:
     SimpleXMLRPCServer.finish_request(self, request, client_address)
   except socket.error:
     pass


if __name__ == "__main__":
  auth_handler = AuthHandler()
  auth_handler.facebook.update({
    'client_id': '188067404574891',
    'client_secret': 'dc62a25223d0bffa96660d9be613caac'
  })
  auth_handler.google.update({
    'client_id': '177344498952.apps.googleusercontent.com',
    'client_secret': 'SIoxPXIC9r45EkmxsCdGoLXT',
  })
  Server(
    ('localhost', 7890),
    Boss(),
    auth_handler=auth_handler
  ).serve_forever()

