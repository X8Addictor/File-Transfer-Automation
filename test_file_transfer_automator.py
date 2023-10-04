from file_transfer_automator import *

def test_server_response():
    test_ftapp = FileTransferAutomator()
    if test_ftapp.FTP_HOSTNAME is not None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((test_ftapp.FTP_HOSTNAME, 22))
        assert result == 0, f"Host is accepting connections on port 22"
        sock.close()
    else:
        assert False

def test_server_login():
    test_ftapp = FileTransferAutomator()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(test_ftapp.FTP_HOSTNAME, port = 22, username = test_ftapp.FTP_LOGIN, password = test_ftapp.FTP_PASSWORD)
    assert ssh.get_transport() is not None, f"SFTP Server has transport - login successful"
    assert ssh.get_transport().is_active() is True, f"SFTP Server has active connection - login successful"
    ssh.close()

def test_config_file():
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

        if None in (FTP_HOSTNAME, FTP_LOGIN, FTP_PASSWORD, FTP_DIRECTORY, LAN_PORT, TIME_OF_DAY_TO_DOWNLOAD):
            raise ValueError("One or more required values are missing in the config file")
        else:
            assert True
    except ValueError as e:
        log_error(f"An error occurred while reading the config file: {e}")
        FTP_HOSTNAME = FTP_LOGIN = FTP_PASSWORD = FTP_DIRECTORY = LAN_PORT = TIME_OF_DAY_TO_DOWNLOAD = None
        assert False
