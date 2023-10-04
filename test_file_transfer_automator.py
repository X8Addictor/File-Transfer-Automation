import socket
import paramiko
import json
from file_transfer_automator import FileTransferAutomator

def test_server_response():
    """
    Test the server's response by checking if it accepts connections on port 22.

    Raises:
        AssertionError: If the FTP_HOSTNAME is None or if the host is not accepting connections on port 22.
    """
    test_ftapp = FileTransferAutomator()
    assert test_ftapp.FTP_HOSTNAME is not None, "FTP_HOSTNAME is None"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((test_ftapp.FTP_HOSTNAME, 22))
    assert result == 0, f"Host is not accepting connections on port 22"
    sock.close()

def test_server_login():
    """
    Test the server login by connecting to the SFTP server.

    Raises:
        AssertionError: If the SFTP server login fails or if there is no active connection after login.
    """
    test_ftapp = FileTransferAutomator()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(test_ftapp.FTP_HOSTNAME, port = 22, username = test_ftapp.FTP_LOGIN, password = test_ftapp.FTP_PASSWORD)
    assert ssh.get_transport() is not None, f"SFTP Server has transport - login failed"
    assert ssh.get_transport().is_active() is True, f"SFTP Server has no active connection - login failed"
    ssh.close()

def test_config_file():
    """
    Test the configuration file by checking if it contains all required values.

    Raises:
        AssertionError: If any of the required values (FTP_HOSTNAME, FTP_LOGIN, FTP_PASSWORD, FTP_DIRECTORY, LAN_PORT, TIME_OF_DAY_TO_DOWNLOAD) are missing in the config file.
    """
    test_ftapp = FileTransferAutomator()
    try:
        with open(test_ftapp.CONFIG_FILE, "r") as config_file:
            config = json.load(config_file)

        FTP_HOSTNAME = config.get('FTP_HOSTNAME')
        FTP_LOGIN = config.get('FTP_LOGIN')
        FTP_PASSWORD = config.get('FTP_PASSWORD')
        FTP_DIRECTORY = config.get('FTP_DIRECTORY')
        LAN_PORT = config.get('LAN_PORT')
        TIME_OF_DAY_TO_DOWNLOAD = config.get('TIME_OF_DAY_TO_DOWNLOAD')

        missing_values = []

        if FTP_HOSTNAME is None or not FTP_HOSTNAME:
            missing_values.append('FTP_HOSTNAME')
        if FTP_LOGIN is None or not FTP_LOGIN:
            missing_values.append('FTP_LOGIN')
        if FTP_PASSWORD is None or not FTP_PASSWORD:    
            missing_values.append('FTP_PASSWORD')
        if FTP_DIRECTORY is None or not FTP_DIRECTORY:
            missing_values.append('FTP_DIRECTORY')
        if LAN_PORT is None or not LAN_PORT:
            missing_values.append('LAN_PORT')
        if TIME_OF_DAY_TO_DOWNLOAD is None or not TIME_OF_DAY_TO_DOWNLOAD:
            missing_values.append('TIME_OF_DAY_TO_DOWNLOAD')

        assert not missing_values, f"Required values are missing in the config file: {', '.join(missing_values)}"
    except ValueError as e:
        assert False, f"An error occurred while reading the config file: {e}"
