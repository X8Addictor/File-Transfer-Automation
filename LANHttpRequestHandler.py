import http.server

class LANHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP request handler for serving files from the 'Server Directory'.

    This class extends the SimpleHTTPRequestHandler from the http.server module
    and sets the directory to 'Server Directory' by default for serving files.

    Args:
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments to pass to the parent class constructor.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory = "Server Directory", **kwargs)
