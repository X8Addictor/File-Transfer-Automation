import os
import logging
import schedule
from ftplib import FTP
import shutil
import time
import http.server
import socketserver
import socket
import _thread as thread
import webbrowser
import LANHttpRequestHandler

# Define constants for file paths and directories.
FILE_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
DOWNLOAD_DIRECTORY = os.path.join(FILE_DIRECTORY, 'File Downloads')
LOG_DIRECTORY = os.path.join(FILE_DIRECTORY, 'Logs')
LOG_FILE = os.path.join(LOG_DIRECTORY, 'Logs.log')
os.makedirs(LOG_DIRECTORY, exist_ok=True)
os.makedirs(DOWNLOAD_DIRECTORY, exist_ok=True)

# Define constants for ftp server
FTP_HOSTNAME = 'test.rebex.net'
FTP_LOGIN = 'demo'
FTP_PASSWORD = 'password'
FTP_DIRECTORY = 'pub/example/'

# Define constants for local area network server
LAN_IP = ""
LAN_PORT = 8000

TIME_OF_DAY_TO_DOWNLOAD = "18:53"

LANServerLaunched = False

def setup_logging():
    """Configure logging settings to save logs to a file."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as log_file:
            log_file.write('')

    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def log_error(message):
    print(f"Error(s) occurred, please check '{LOG_FILE}' for more details")
    logging.error(message)

def log_success(message):
    print(message)
    logging.info(message)

def main():
    try:
        log_success(f"Logging into ftp server at {FTP_HOSTNAME}...")
        server = FTP(FTP_HOSTNAME)
        server.encoding = "utf-8"
        server.login(user = FTP_LOGIN, passwd = FTP_PASSWORD)
        log_success(f"Logged in successfully as {FTP_LOGIN}")
        server.cwd(FTP_DIRECTORY)
        log_success(f"Changed directory successfully")
        list_of_files = server.nlst()
        log_success(f"Successfully retrieved list of files and directories")
        for file in list_of_files:
            if ".png" in file or ".txt" in file:
                log_success(f"Found a suitable file for downloading, called '{file}'")
                with open(f"{DOWNLOAD_DIRECTORY}/{file}", "wb") as f:
                    server.retrbinary(f"RETR {file}", f.write)
                    log_success(f"Successfully downloaded '{file}' to local directory")
        server.quit()
        log_success(f"Logged out of server {FTP_HOSTNAME} successfully")
        log_success(f"Will download these files again tomorrow at {TIME_OF_DAY_TO_DOWNLOAD}")

        global LANServerLaunched
        if LANServerLaunched == False:
            thread.start_new_thread(serve_up_on_lan, ())
            LANServerLaunched = True
            webbrowser.get('firefox').open(f"{LAN_IP}:{LAN_PORT}", new = 2)
        else:
            log_success(f"LAN Server already running")

    except Exception as e:
        log_error(f"{e}\n")

def getLocalIPAddress():
    global LAN_IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('192.168.1.1', 1))
        LAN_IP = s.getsockname()[0]
    except Exception:
        LAN_IP = '127.0.0.1'
    finally:
        s.close()

def serve_up_on_lan():
    try:
        handler = LANHttpRequestHandler
        with socketserver.TCPServer((LAN_IP, LAN_PORT), handler) as httpd:
            log_success(f"Server started at {LAN_IP}:{LAN_PORT}")
            httpd.serve_forever()
    except Exception as e:
        log_error(f"{e}\n")

def run_scheduled_task():
    schedule.every().day.at(TIME_OF_DAY_TO_DOWNLOAD).do(main)
    log_success(f"Will download files at {TIME_OF_DAY_TO_DOWNLOAD}")
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        log_success("Script exiting while waiting for scheduled task...")
    finally:
        pass

if __name__ == '__main__':
    setup_logging()
    getLocalIPAddress()
    run_scheduled_task()
