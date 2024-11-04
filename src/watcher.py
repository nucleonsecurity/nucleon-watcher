import sys
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
import hashlib
import json
import argparse
from operations import *


from dotenv import load_dotenv
load_dotenv() 
API_KEY = os.environ.get("malprob_key")


class Watcher:

    def __init__(self,watched_directory):
        self.observer = Observer()
        self.watched_directory = watched_directory
    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.watched_directory, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except:
            self.observer.stop()
            print("Observer Stopped")

        self.observer.join()

class Handler(FileSystemEventHandler):

    @staticmethod
    def on_any_event(event):
        if event.is_directory:
            return None

        
        elif event.event_type == 'modified' or event.event_type == 'created':
            # Added example to handle modified files
            print(f"New file is tracked - {event.src_path}.")
            detector = Detector(api_key=API_KEY,file_path=event.src_path)
            print('File sha256 is :',detector.get_file_hash())
            try: 
                detector.send_file_to_scan()
            except Exception as e:
                print("Error", f"An error occurred: {str(e)}")
            time.sleep(5)
            result = None
            try :
                result = detector.send_file_to_api()
            except Exception as e:
                print("Error", f"An error occurred: {str(e)}")
            # print(type(result))
            responder = Responder(file_path=event.src_path)
            label = result.get('label',None)
            if label == 'malware':
                
                print("File is malicious")
                responder.quarantine()
            elif label == 'suspicious':
                print("File is suspecious")
                responder.quarantine()
            elif label == 'benign':
                print("File is benign")
                
            else:
                print("Error", "An error occurred while processing the file.")
                

if __name__ == '__main__':
    print("Starting Watcher, watching directory for changes ...")
    parser = argparse.ArgumentParser(description='Nucleon Watcher')
    parser.add_argument('--watched_directory', type=str, help='Directory to watch')
    args = parser.parse_args()
    watched_directory = args.watched_directory
    w = Watcher(watched_directory=watched_directory)
    w.run()
