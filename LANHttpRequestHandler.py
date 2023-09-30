import http.server

class LANHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.path = "File Downloads/"
        return http.server.SimpleHTTPRequestHandler.do_GET(self)