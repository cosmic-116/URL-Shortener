"""Serve the standalone Snip design preview on localhost, without dependencies."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from functools import partial
import argparse
import webbrowser

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=4173)
    parser.add_argument('--open', dest='open_browser', action='store_true')
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    handler = partial(SimpleHTTPRequestHandler, directory=str(directory))
    with ThreadingHTTPServer(('127.0.0.1', args.port), handler) as server:
        print(f'Snip preview: http://127.0.0.1:{args.port}', flush=True)
        print('Press Ctrl+C to stop. All data is simulated.', flush=True)
        if args.open_browser:
            webbrowser.open(f'http://127.0.0.1:{args.port}')
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
