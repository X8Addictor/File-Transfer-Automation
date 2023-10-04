# File Transfer Automation

This project is a Python-based automation script for transferring files between an FTP server and a local LAN server. It also includes a local LAN server for serving the transferred files within the network.

## Features

- Automated file transfer between FTP server and local server.
- Scheduled task to initiate file downloads at a specified time.
- Self-signed SSL certificate generation for secure LAN server communication.
- Logging of events and errors for troubleshooting.

## Prerequisites

Before using this automation script, ensure you have the following:

- Python 3 installed on your system.
- Required Python packages installed. You can install them using `pip install -r requirements.txt`.
- Configuration file (`config.json`) with FTP server and automation settings.

## Usage

1. Clone this repository to your local machine.
   ```bash
   git clone https://github.com/X8Addictor/File-Transfer-Automation
   ```

3. Configure the `config.json` file with the FTP server details and automation settings:

    ```json
    {
        "FTP_HOSTNAME": "ftp.example.com",
        "FTP_LOGIN": "your_ftp_username",
        "FTP_PASSWORD": "your_ftp_password",
        "FTP_DIRECTORY": "/remote/directory/path",
        "LAN_PORT": 8080,
        "TIME_OF_DAY_TO_DOWNLOAD": "23:59"
    }
    ```

    - `FTP_HOSTNAME`: Hostname or IP address of the FTP server.
    - `FTP_LOGIN`: FTP server login username.
    - `FTP_PASSWORD`: FTP server login password.
    - `FTP_DIRECTORY`: Directory on the FTP server where files are located.
    - `LAN_PORT`: Port for the local LAN server.
    - `TIME_OF_DAY_TO_DOWNLOAD`: Time of day to initiate file downloads in 24-hour format (e.g., "23:59").

4. Run the automation script:

    ```bash
    python file_transfer_automatior.py
    ```

5. The script will initiate file downloads at the specified time and serve them on the local LAN server.

## Testing

This project includes test scripts for checking server responses, login functionality, and configuration file validity. To run the tests, use the following commands:

- Server Response Test:

    ```bash
    python -m unittest test_file_transfer_automatior.test_server_response
    ```

- Server Login Test:

    ```bash
    python -m unittest test_file_transfer_automatior.test_server_login
    ```

- Configuration File Test:

    ```bash
    python -m unittest test_file_transfer_automatior.test_config_file
    ```
