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
import datetime
from LANHttpRequestHandler import LANHttpRequestHandler
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

# Define constants for file paths and directories.
FILE_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
DOWNLOAD_DIRECTORY = os.path.join(FILE_DIRECTORY, 'File Downloads')
LOG_DIRECTORY = os.path.join(FILE_DIRECTORY, 'Logs')
SSL_CERTIFICATE_DIRECTORY = os.path.join(FILE_DIRECTORY, 'ssl certificate')
SSL_CERTIFICATE_FILE = os.path.join(SSL_CERTIFICATE_DIRECTORY, 'ssl_certificate.crt')
SSL_PRIVATE_KEY_FILE = os.path.join(SSL_CERTIFICATE_DIRECTORY, 'ssl_key.key')
LOG_FILE = os.path.join(LOG_DIRECTORY, 'Logs.log')
CONFIG_FILE = os.path.join(FILE_DIRECTORY, 'config.json')
os.makedirs(LOG_DIRECTORY, exist_ok = True)
os.makedirs(DOWNLOAD_DIRECTORY, exist_ok = True)
os.makedirs(SSL_CERTIFICATE_DIRECTORY, exist_ok = True)

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

def generate_self_signed_certificate_and_key(days_valid = 365):
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

        with open(SSL_PRIVATE_KEY_FILE, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=NoEncryption(),
                )
            )

        with open(SSL_CERTIFICATE_FILE, "wb") as cert_file:
            cert_file.write(
                certificate.public_bytes(
                    encoding=Encoding.PEM,
                )
            )

        log_success("Self-signed certificate and key generated successfully.")
    except Exception as e:
        log_error(f"Error generating self-signed certificate and key: {e}\n")


def log_error(message):
    print(f"Error(s) occurred, please check '{LOG_FILE}' for more details")
    logging.error(message)

def log_success(message):
    print(message)
    logging.info(message)

def main():
    try:
        if not FTP_HOSTNAME or not FTP_LOGIN or not FTP_PASSWORD or not FTP_DIRECTORY:
            raise ValueError("FTP configuration is incomplete.")

        log_success(f"Logging into SFTP server at {FTP_HOSTNAME}...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(FTP_HOSTNAME, port = 22, username = FTP_LOGIN, password = FTP_PASSWORD)

        sftp = ssh.open_sftp()
        log_success(f"Logged in successfully as {FTP_LOGIN}")
        sftp.chdir(FTP_DIRECTORY)
        log_success(f"Changed directory successfully")
        list_of_files = sftp.listdir()
        log_success(f"Successfully retrieved list of files")
        log_success(f"Beginning download of files...")
        
        for file in list_of_files:
            local_file_path = os.path.join(DOWNLOAD_DIRECTORY, file)
            sftp.get(file, local_file_path)
            log_success(f"Successfully downloaded '{file}' to local directory")
        log_success(f"Successfully downloaded all files.")

        sftp.close()
        ssh.close()
        log_success(f"Logged out of server {FTP_HOSTNAME} successfully")
        log_success(f"Will download these files again tomorrow at {TIME_OF_DAY_TO_DOWNLOAD}")

        launch_lan_server()
    except paramiko.AuthenticationException as e_auth:
        log_error(f"SFTP Authentication Error: {e_auth}")
    except paramiko.SSHException as e_ssh:
        log_error(f"SFTP SSH Error: {e_ssh}")
    except ValueError as e_value:
        log_error(f"Value Error: {e_value}")
    except Exception as e:
        log_error(f"An unexpected error occurred: {e}\n")

def launch_lan_server():
    global LANServerLaunched
    try:
        if not LANServerLaunched:
            thread.start_new_thread(serve_up_on_lan, ())
            LANServerLaunched = True
            webbrowser.open(f"https://{LAN_IP}:{LAN_PORT}")
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
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        if not os.path.exists(SSL_CERTIFICATE_FILE):
            log_error(f"SSL certificate file does not exist: {SSL_CERTIFICATE_FILE}")
            return None

        if not os.path.exists(SSL_PRIVATE_KEY_FILE):
            log_error(f"SSL private key file does not exist: {SSL_PRIVATE_KEY_FILE}")
            return None

        ssl_context.load_cert_chain(certfile = SSL_CERTIFICATE_FILE, keyfile = SSL_PRIVATE_KEY_FILE) # Replace the certificate and private key with a real one

        with socketserver.TCPServer((LAN_IP, LAN_PORT), handler) as httpd:
            httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side = True)
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
    except Exception as e:
        log_error(f"An unexpected error occurred: {e}\n")
    finally:
        pass

if __name__ == '__main__':
    setup_logging()
    load_configuration()
    generate_self_signed_certificate_and_key()
    get_local_ip_address()
    run_scheduled_task()
