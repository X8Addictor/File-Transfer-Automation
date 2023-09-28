import os
import logging
import schedule
from ftplib import FTP
import shutil
import time

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

TIME_OF_DAY_TO_DOWNLOAD = "17:41"

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
    run_scheduled_task()
