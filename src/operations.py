import hashlib
import requests
import json
import os
import shutil
import zipfile
import time
import logging
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename="application.log",  # Log file name
    filemode="a",  # Append to the log file
)

# Constants
DOMAIN_NAME = "https://malprob.io"
TIMEOUT = 120
POLL_INTERVAL = 5
MAX_WAIT_TIME = 600


def get_file_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""
    try:
        with open(file_path, "rb") as f:
            sha256 = hashlib.sha256()
            while chunk := f.read(8192):
                sha256.update(chunk)
            return sha256.hexdigest()
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
    except Exception as e:
        logging.error(f"An error occurred while calculating SHA-256: {e}")


def wait_for_status_code(url, status_code, timeout=MAX_WAIT_TIME):
    """Wait for a specific HTTP status code from a URL within a timeout period."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == status_code:
                return True
            if response.status_code == 404:
                return False
            time.sleep(POLL_INTERVAL)
        except requests.RequestException as e:
            logging.error(f"Error while waiting for status code: {e}")
            return None
    logging.warning("Timeout exceeded while waiting for status code.")
    return None


class Detector:
    """Handles file scanning and reporting using an external API."""

    def __init__(self, api_key, file_path):
        self.api_key = api_key
        self.file_path = file_path

    def get_file_hash(self):
        """Compute the SHA-256 hash of the file."""
        return get_file_sha256(self.file_path)

    def send_file_to_api(self):
        """Send a file for scanning and retrieve the result."""
        try:
            file_hash = self.get_file_hash()
            if not file_hash:
                return None

            result = self.get_file_report(file_hash)
            return result
        except Exception as e:
            logging.error(f"Error sending file to API: {e}")
            return None

    def get_file_report(self, hashcode):
        """Fetch the report for a file hash."""
        url = f"{DOMAIN_NAME}/api/search/{hashcode}"
        try:
            if wait_for_status_code(url, 200):
                response = requests.get(
                    url,
                    headers={"Authorization": f"Token {self.api_key}"},
                    timeout=TIMEOUT,
                )
                if response.status_code == 200:
                    return response.json()
                logging.error(
                    f"Request failed with status code {response.status_code}: {response.text}"
                )
            else:
                logging.warning(
                    "Status code 200 not received within the timeout period."
                )
        except requests.RequestException as e:
            logging.error(f"Error while fetching file report: {e}")
        return None

    def send_file_to_scan(self):
        """Upload a file for scanning."""
        try:
            with open(self.file_path, "rb") as f:
                response = requests.post(
                    f"{DOMAIN_NAME}/api/scan/",
                    files={"file": f},
                    headers={"Authorization": f"Token {self.api_key}"},
                    timeout=TIMEOUT,
                )
            if response.status_code == 200:
                logging.info("File successfully sent for scanning.")
            else:
                logging.error(
                    f"Request failed with status code {response.status_code}: {response.text}"
                )
        except Exception as e:
            logging.error(f"Error sending file to scan: {e}")

    def send_file_hash_to_rescan(self, file_hash):
        """Request a rescan for a specific file hash."""
        try:
            response = requests.post(
                f"{DOMAIN_NAME}/api/rescan/",
                json={"hash": file_hash},
                headers={"Authorization": f"Token {self.api_key}"},
                timeout=TIMEOUT,
            )
            if response.status_code == 200:
                logging.info("File hash sent for rescanning successfully.")
            else:
                logging.error(
                    f"Request failed with status code {response.status_code}: {response.text}"
                )
        except Exception as e:
            logging.error(f"Error sending file hash to rescan: {e}")


class Responder:
    """Handles actions to be taken on a file, such as delete, move, or quarantine."""

    def __init__(self, file_path):
        self.file_path = file_path

    def delete_file(self):
        """Delete the file at the specified path."""
        try:
            os.remove(self.file_path)
            logging.info(f"File {self.file_path} has been deleted.")
        except FileNotFoundError:
            logging.error(f"No file found at {self.file_path} to delete.")
        except Exception as e:
            logging.error(f"Error deleting file: {e}")

    def move_file(self, destination):
        """Move the file to a new location."""
        try:
            shutil.move(self.file_path, destination)
            logging.info(f"File has been moved to {destination}")
        except FileNotFoundError:
            logging.error(f"No file found at {self.file_path} to move.")
        except Exception as e:
            logging.error(f"Error moving file: {e}")

    def quarantine(self):
        """Quarantine the file by zipping it and storing it securely."""
        sha256 = get_file_sha256(self.file_path)
        if not sha256:
            return

        output_zip = f"./infected_{sha256}.zip"

        if not os.path.isfile(self.file_path):
            logging.error(f"Error: {self.file_path} does not exist.")
            return

        try:
            with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(self.file_path, os.path.basename(self.file_path))
            logging.info(
                f"File {self.file_path} has been quarantined into {output_zip}"
            )
        except Exception as e:
            logging.error(f"Error quarantining file: {e}")
