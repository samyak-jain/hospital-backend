import os
import tornado.auth
import tornado.gen
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web

from motor import MotorClient
from tornado.options import define, options

define("port", default=8000, help="runs on the given port", type=int)


class AuthHandler(tornado.web.RequestHandler):
    @tornado.gen.coroutine
    def get(self, *args, **kwargs):
        pass


if __name__ == "__main__":
    tornado.options.parse_command_line()
    settings = {
        'default_handler_args': dict(status_code=404),
        'debug': True
    }
    app = tornado.web.Application(
        handlers=[
            (r'/login', AuthHandler)
        ], **settings
    )
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(os.environ.get("PORT",options.port))
    tornado.ioloop.IOLoop.instance().start()