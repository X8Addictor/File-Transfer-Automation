import os
import logging
import schedule
import time
import socketserver
import socket
import _thread as thread
import webbrowser
import json
import paramiko
import ssl
import shutil
import datetime
from LANHttpRequestHandler import LANHttpRequestHandler
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

class FileTransferAutomator:
    """
    A class for automating file transfers between an FTP server and a local LAN server.

    Attributes:
        FILE_DIRECTORY (str): The path to the directory containing this script.
        DOWNLOAD_DIRECTORY (str): The directory where downloaded files are stored.
        LOG_DIRECTORY (str): The directory where log files are stored.
        SERVER_DIRECTORY (str): The directory for the local LAN server files.
        SSL_CERTIFICATE_DIRECTORY (str): The directory for SSL certificates.
        SSL_CERTIFICATE_FILE (str): The path to the SSL certificate file.
        SSL_PRIVATE_KEY_FILE (str): The path to the SSL private key file.
        LOG_FILE (str): The path to the log file.
        CONFIG_FILE (str): The path to the configuration file.
        FTP_HOSTNAME (str): The hostname of the FTP server.
        FTP_LOGIN (str): The FTP server login username.
        FTP_PASSWORD (str): The FTP server login password.
        FTP_DIRECTORY (str): The FTP server directory for file transfers.
        LAN_IP (str): The local area network server's IP address.
        LAN_PORT (int): The port on which the LAN server runs.
        TIME_OF_DAY_TO_DOWNLOAD (str): The time of day to initiate file downloads.
        LANServerLaunched (bool): Indicates whether the LAN server has been launched.
        MAX_RETRIES (int): The maximum number of download retries in case of failure.
        RETRY_INTERVAL_SECONDS (int): The interval between download retries.
    """
    def __init__(self):
        """
        Initialize the FileTransferAutomator and perform setup tasks.
        """
        # Attributes for file paths and directories.
        self.FILE_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
        self.DOWNLOAD_DIRECTORY = os.path.join(self.FILE_DIRECTORY, 'File Downloads')
        self.LOG_DIRECTORY = os.path.join(self.FILE_DIRECTORY, 'Logs')
        self.SERVER_DIRECTORY = os.path.join(self.FILE_DIRECTORY, 'Server Directory')
        self.SSL_CERTIFICATE_DIRECTORY = os.path.join(self.FILE_DIRECTORY, 'ssl certificate')
        self.SSL_CERTIFICATE_FILE = os.path.join(self.SSL_CERTIFICATE_DIRECTORY, 'ssl_certificate.crt')
        self.SSL_PRIVATE_KEY_FILE = os.path.join(self.SSL_CERTIFICATE_DIRECTORY, 'ssl_key.key')
        self.LOG_FILE = os.path.join(self.LOG_DIRECTORY, 'Logs.log')
        self.CONFIG_FILE = os.path.join(self.FILE_DIRECTORY, 'config.json')
        os.makedirs(self.LOG_DIRECTORY, exist_ok = True)
        os.makedirs(self.DOWNLOAD_DIRECTORY, exist_ok = True)
        os.makedirs(self.SERVER_DIRECTORY, exist_ok = True)
        os.makedirs(self.SSL_CERTIFICATE_DIRECTORY, exist_ok = True)

        # Attributes for ftp server
        self.FTP_HOSTNAME = None
        self.FTP_LOGIN = None
        self.FTP_PASSWORD = None
        self.FTP_DIRECTORY = None

        # Attributes for local area network server
        self.LAN_IP = None
        self.LAN_PORT = None

        # Attributes for schedule and LAN server
        self.TIME_OF_DAY_TO_DOWNLOAD = None
        self.LANServerLaunched = False

        # Attributes for settings for scheduled task
        self.MAX_RETRIES = 3
        self.RETRY_INTERVAL_SECONDS = 5

        # Calling methods to start the automation
        self.setup_logging()
        self.load_configuration()
        self.generate_self_signed_certificate_and_key()
        self.get_local_ip_address()

    def run(self):
        """
        Run the file transfer automation.
        """
        self.run_scheduled_task()

    def setup_logging(self):
        """
        Configure logging settings to save logs to a file.
        """
        if not os.path.exists(self.LOG_FILE):
            with open(self.LOG_FILE, 'w') as log_file:
                log_file.write('')

        logging.basicConfig(filename=self.LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

    def load_configuration(self):
        """
        Load configuration settings from the configuration file.
        """
        try:
            with open(self.CONFIG_FILE, "r") as config_file:
                config = json.load(config_file)

            self.FTP_HOSTNAME = config.get('FTP_HOSTNAME')
            self.FTP_LOGIN = config.get('FTP_LOGIN')
            self.FTP_PASSWORD = config.get('FTP_PASSWORD')
            self.FTP_DIRECTORY = config.get('FTP_DIRECTORY')
            self.LAN_PORT = config.get('LAN_PORT')
            self.TIME_OF_DAY_TO_DOWNLOAD = config.get('TIME_OF_DAY_TO_DOWNLOAD')

            if None in (self.FTP_HOSTNAME, self.FTP_LOGIN, self.FTP_PASSWORD, self.FTP_DIRECTORY, self.LAN_PORT, self.TIME_OF_DAY_TO_DOWNLOAD):
                raise ValueError("One or more required values are missing in the config file")

        except ValueError as e:
            log_error(f"An error occurred while reading the config file: {e}")
            self.FTP_HOSTNAME = self.FTP_LOGIN = self.FTP_PASSWORD = self.FTP_DIRECTORY = self.LAN_PORT = self.TIME_OF_DAY_TO_DOWNLOAD = None

    def generate_self_signed_certificate_and_key(self, days_valid = 365):
        """
        Generate a self-signed SSL certificate and private key.
        
        Args:
            days_valid (int): Number of days the certificate is valid.
        """
        try:
            common_name = socket.gethostname()

            # Generate a new private key
            private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)

            # Create a self-signed certificate
            subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
            certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            ).sign(
                private_key, hashes.SHA256()
            )

            with open(self.SSL_PRIVATE_KEY_FILE, "wb") as key_file:
                key_file.write(
                    private_key.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=NoEncryption(),
                    )
                )

            with open(self.SSL_CERTIFICATE_FILE, "wb") as cert_file:
                cert_file.write(
                    certificate.public_bytes(
                        encoding=Encoding.PEM,
                    )
                )

            self.log_success("Self-signed certificate and key generated successfully.")
        except Exception as e:
            self.log_error(f"Error generating self-signed certificate and key: {e}\n")

    def log_error(self, message):
        """
        Log an error message.

        Args:
            message (str): The error message to log.
        """
        print(f"Error(s) occurred, please check '{self.LOG_FILE}' for more details")
        logging.error(message)

    def log_success(self, message):
        """
        Log a success message.

        Args:
            message (str): The success message to log.
        """
        print(message)
        logging.info(message)

    def main(self):
        """
        Perform the main file transfer automation tasks.
        """
        try:
            if not self.FTP_HOSTNAME or not self.FTP_LOGIN or not self.FTP_PASSWORD or not self.FTP_DIRECTORY:
                raise ValueError("FTP configuration is incomplete.")

            self.log_success(f"Logging into SFTP server at {self.FTP_HOSTNAME}...")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.FTP_HOSTNAME, port = 22, username = self.FTP_LOGIN, password = self.FTP_PASSWORD)

            sftp = ssh.open_sftp()
            self.log_success(f"Logged in successfully as {self.FTP_LOGIN}")
            sftp.chdir(self.FTP_DIRECTORY)
            self.log_success(f"Changed directory successfully to {self.FTP_DIRECTORY}")
            list_of_files = sftp.listdir()
            self.log_success(f"Successfully retrieved list of files")
            self.log_success(f"Beginning download of files...")

            for file in list_of_files:
                local_file_path = os.path.join(self.DOWNLOAD_DIRECTORY, file)
                sftp.get(file, local_file_path)
                self.log_success(f"Successfully downloaded '{file}' to local directory")
            self.log_success(f"Successfully downloaded all files.")

            sftp.close()
            ssh.close()
            self.log_success(f"Logged out of server {self.FTP_HOSTNAME} successfully")
            self.log_success(f"Will download these files again tomorrow at {self.TIME_OF_DAY_TO_DOWNLOAD}")

            self.copy_files_to_server_directory()

            self.launch_lan_server()

        except paramiko.AuthenticationException as e_auth:
            self.log_error(f"SFTP Authentication Error: {e_auth}")
        except paramiko.SSHException as e_ssh:
            self.log_error(f"SFTP SSH Error: {e_ssh}")
        except ValueError as e_value:
            self.log_error(f"Value Error: {e_value}")
        except Exception as e:
            self.log_error(f"An unexpected error occurred: {e}\n")

    def copy_files_to_server_directory(self):
        """
        Copy downloaded files to the local server directory.
        """
        self.log_success(f"Copying files to local server...")
        try:
            files = os.listdir(self.DOWNLOAD_DIRECTORY)
            for file in files:
                shutil.copy(os.path.join(self.DOWNLOAD_DIRECTORY, file), self.SERVER_DIRECTORY)
                self.log_success(f"Copied file '{file}' to local server directory")
        except Exception as e:
            self.log_error(f"An unexpected error occurred: {e}\n")

    def launch_lan_server(self):
        """
        Launch the local LAN server.
        """
        try:
            if not self.LANServerLaunched:
                thread.start_new_thread(self.serve_up_on_lan, ())
                self.LANServerLaunched = True
                webbrowser.open(f"https://{self.LAN_IP}:{self.LAN_PORT}")
            else:
                self.log_success(f"LAN Server already running")
        except Exception as e:
            self.log_error(f"Error launching LAN Server: {e}\n")

    def get_local_ip_address(self):
        """
        Get the local IP address.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(('192.168.1.1', 1))
            self.LAN_IP = s.getsockname()[0]
        except Exception:
            self.LAN_IP = '127.0.0.1'
        finally:
            s.close()

    def serve_up_on_lan(self):
        """
        Serve content on the LAN via HTTPS.
        """
        try:
            handler = LANHttpRequestHandler
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

            if not os.path.exists(self.SSL_CERTIFICATE_FILE):
                self.log_error(f"SSL certificate file does not exist: {self.SSL_CERTIFICATE_FILE}")
                return None

            if not os.path.exists(self.SSL_PRIVATE_KEY_FILE):
                self.log_error(f"SSL private key file does not exist: {self.SSL_PRIVATE_KEY_FILE}")
                return None

            # Add the generated certificate to the browser in the lan network or ignore warnings in the browser
            ssl_context.load_cert_chain(certfile = self.SSL_CERTIFICATE_FILE, keyfile = self.SSL_PRIVATE_KEY_FILE)
            with socketserver.TCPServer((self.LAN_IP, self.LAN_PORT), handler) as httpd:
                httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side = True)
                self.log_success(f"Server started at https://{self.LAN_IP}:{self.LAN_PORT}")
                httpd.serve_forever()
        except Exception as e:
            self.log_error(f"Error serving on LAN: {e}\n")

    def scheduled_task_with_retry(self):
        """
        Run the scheduled task with retry mechanism.
        """
        retries = 0
        while retries < self.MAX_RETRIES:
            try:
                self.main()
                break  # Successful download, no need to retry
            except Exception as e:
                self.log_error(f"Error in scheduled task: {e}")
                retries += 1
                if retries < self.MAX_RETRIES:
                    self.log_success(f"Retrying in {self.RETRY_INTERVAL_SECONDS} seconds...")
                    time.sleep(self.RETRY_INTERVAL_SECONDS)
        else:
            self.log_error(f"Max retries reached. Scheduled task failed.")

    def run_scheduled_task(self):
        """
        Run the scheduled task to initiate file downloads.
        """
        schedule.every().day.at(self.TIME_OF_DAY_TO_DOWNLOAD).do(self.scheduled_task_with_retry)
        self.log_success(f"Will download files at {self.TIME_OF_DAY_TO_DOWNLOAD}")
        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            self.log_success("Script exiting while waiting for scheduled task...")
        except Exception as e:
            self.log_error(f"An unexpected error occurred: {e}\n")
        finally:
            pass

if __name__ == '__main__':
    ftapp = FileTransferAutomator()
    ftapp.run()
