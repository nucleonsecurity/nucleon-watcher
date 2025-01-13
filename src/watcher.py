import sys
import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import argparse
from dotenv import load_dotenv
from colorama import Fore, Style, init
from operations import Detector, Responder

# Initialize colorama and dotenv
init(autoreset=True)
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename="watcher.log",  # Log file for the watcher script
    filemode="a",
)

# Get API key from environment
API_KEY = os.getenv("malprob_key")
if not API_KEY:
    logging.error("API key not found. Make sure MALPROB_KEY is set in the environment.")
    sys.exit("Error: API key not configured.")


class Watcher:
    """Observes a directory and triggers actions on file changes."""

    def __init__(self, watched_directory):
        self.observer = Observer()
        self.watched_directory = watched_directory

    def run(self):
        """Starts the observer to monitor the directory."""
        logging.info(f"Starting watcher for directory: {self.watched_directory}")
        event_handler = Handler()
        self.observer.schedule(event_handler, self.watched_directory, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            logging.info("Stopping observer...")
            print(Fore.BLUE + "Stopping observer...")
            self.observer.stop()

        self.observer.join()


class Handler(FileSystemEventHandler):
    """Handles events triggered by file changes."""

    @staticmethod
    def on_any_event(event):
        """Handles all file-related events."""
        if event.is_directory:
            logging.debug(f"Ignoring directory event: {event.src_path}")
            return

        if event.event_type == "created":
            logging.info(f"New file detected: {event.src_path}")
            print(Fore.BLUE + f"New file detected: {event.src_path}")

            detector = Detector(api_key=API_KEY, file_path=event.src_path)

            try:
                # Get the file hash
                file_hash = detector.get_file_hash()
                if not file_hash:
                    logging.error(f"Failed to compute file hash for {event.src_path}")
                    print(
                        Fore.RED + f"Failed to compute file hash for {event.src_path}"
                    )
                    return

                logging.info(f"File hash for {event.src_path}: {file_hash}")

                # Send the file for scanning
                detector.send_file_to_scan()
                logging.info(f"File sent for scanning: {event.src_path}")

                # Wait and retrieve scan result
                time.sleep(5)
                result = detector.send_file_to_api()
                if result:
                    logging.info(f"Scan result for {event.src_path}: {result}")
                    label = result.get("label", None)
                    responder = Responder(file_path=event.src_path)

                    if label == "malware":
                        logging.warning(f"File identified as malware: {event.src_path}")
                        print(Fore.RED + "Malprob verdict: File is malicious")
                        responder.quarantine()
                    elif label == "suspicious":
                        logging.warning(
                            f"File identified as suspicious: {event.src_path}"
                        )
                        print(Fore.YELLOW + "Malprob verdict: File is suspicious")
                        responder.quarantine()
                    elif label == "benign":
                        logging.info(f"File identified as benign: {event.src_path}")
                        print(Fore.GREEN + "Malprob verdict: File is benign")
                    else:
                        logging.error(
                            f"Unexpected label in scan result for {event.src_path}: {result}"
                        )
                        print(Fore.RED + "Error: Unable to process the file verdict.")
                else:
                    logging.error(
                        f"Failed to retrieve scan result for {event.src_path}"
                    )
                    print(Fore.RED + "Error: Failed to retrieve scan result.")
            except Exception as e:
                logging.error(f"Error processing file {event.src_path}: {e}")
                print(Fore.RED + f"Error processing file {event.src_path}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Directory Watcher for Malicious Files"
    )
    parser.add_argument(
        "--watched_directory",
        type=str,
        required=True,
        help="Path to the directory to watch",
    )
    args = parser.parse_args()

    watched_directory = args.watched_directory
    if not os.path.isdir(watched_directory):
        logging.error(f"Directory not found: {watched_directory}")
        sys.exit(f"Error: Directory not found: {watched_directory}")

    logging.info(f"Starting Watcher... Watching directory: {watched_directory}")
    print(Fore.BLUE + f"Starting Watcher... Watching directory: {watched_directory}")
    watcher = Watcher(watched_directory)
    watcher.run()
