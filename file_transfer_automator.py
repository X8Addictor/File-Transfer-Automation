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
from LANHttpRequestHandler import LANHttpRequestHandler
import json

# Define constants for file paths and directories.
FILE_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
DOWNLOAD_DIRECTORY = os.path.join(FILE_DIRECTORY, 'File Downloads')
LOG_DIRECTORY = os.path.join(FILE_DIRECTORY, 'Logs')
LOG_FILE = os.path.join(LOG_DIRECTORY, 'Logs.log')
CONFIG_FILE = os.path.join(FILE_DIRECTORY, 'config.json')
os.makedirs(LOG_DIRECTORY, exist_ok=True)
os.makedirs(DOWNLOAD_DIRECTORY, exist_ok=True)

# Define constants for ftp server
FTP_HOSTNAME = None
FTP_LOGIN = None
FTP_PASSWORD = None
FTP_DIRECTORY = None

# Define constants for local area network server
LAN_IP = None
LAN_PORT = None

TIME_OF_DAY_TO_DOWNLOAD = None
LANServerLaunched = False

def setup_logging():
    """Configure logging settings to save logs to a file."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as log_file:
            log_file.write('')

    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def load_configuration():
    global FTP_HOSTNAME, FTP_LOGIN, FTP_PASSWORD, FTP_DIRECTORY, LAN_PORT, TIME_OF_DAY_TO_DOWNLOAD

    try:
        with open(CONFIG_FILE, "r") as config_file:
            config = json.load(config_file)

        FTP_HOSTNAME = config.get('FTP_HOSTNAME')
        FTP_LOGIN = config.get('FTP_LOGIN')
        FTP_PASSWORD = config.get('FTP_PASSWORD')
        FTP_DIRECTORY = config.get('FTP_DIRECTORY')
        LAN_PORT = config.get('LAN_PORT')
        TIME_OF_DAY_TO_DOWNLOAD = config.get('TIME_OF_DAY_TO_DOWNLOAD')

        if None in (FTP_HOSTNAME, FTP_LOGIN, FTP_PASSWORD, FTP_DIRECTORY, LAN_PORT, TIME_OF_DAY_TO_DOWNLOAD):
            raise ValueError("One or more required values are missing in the config file")

    except ValueError as e:
        log_error(f"An error occurred while reading the config file: {e}")
        FTP_HOSTNAME = FTP_LOGIN = FTP_PASSWORD = FTP_DIRECTORY = LAN_PORT = TIME_OF_DAY_TO_DOWNLOAD = None

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
            if file.endswith((".png", ".txt")):
                log_success(f"Found a suitable file for downloading, called '{file}'")
                local_file_path = os.path.join(DOWNLOAD_DIRECTORY, file)
                with open(local_file_path, "wb") as local_file:
                    server.retrbinary(f"RETR {file}", local_file.write)
                    log_success(f"Successfully downloaded '{file}' to local directory")

        server.quit()
        log_success(f"Logged out of server {FTP_HOSTNAME} successfully")
        log_success(f"Will download these files again tomorrow at {TIME_OF_DAY_TO_DOWNLOAD}")

        launch_lan_server()
    except error_perm as e_perm:
        log_error(f"FTP Permission Error: {e_perm}")
    except error_reply as e_reply:
        log_error(f"FTP Reply Error: {e_reply}")
    except Exception as e:
        log_error(f"An unexpected error occurred: {e}\n")

def launch_lan_server():
    global LANServerLaunched
    try:
        if not LANServerLaunched:
            thread.start_new_thread(serve_up_on_lan, ())
            LANServerLaunched = True
            #webbrowser.get().open(f"{LAN_IP}:{LAN_PORT}")
        else:
            log_success(f"LAN Server already running")
    except Exception as e:
        log_error(f"Error launching LAN Server: {e}\n")

def get_local_ip_address():
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
        log_error(f"Error serving on LAN: {e}\n")

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
    load_configuration()
    get_local_ip_address()
    run_scheduled_task()
