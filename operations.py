import hashlib
import requests 
import json
import subprocess
import os
import shutil
import zipfile
import time
# import pyminizip

class Detector:
    def __init__(self,api_key,file_path):
        self.api_key = api_key
        self.file_path = file_path

    def get_file_hash(self):
        try:
            sha256 = hashlib.sha256()
            with open(self.file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except PermissionError as e:
            print(f"Error: {e}. Unable to access the file {self.file_path}. Please check file permissions.")

    def send_file_to_api(self):
        try:
            file_hash = self.get_file_hash()
            result = self.get_file_report(file_hash)
            return result
        except Exception as e:
            print("Error", f"An error occurred: {str(e)}")
            return None

    def get_file_report(self,hashcode):
        try:
            response = requests.get(
                f"https://malprob.io/api/search/{hashcode}",
                headers={"Authorization": f"Token {self.api_key}"},
                timeout=120,
            )

            if response.status_code == 200:
                result = response.json()
                return result
            elif response.status_code == 404:
                self.send_file_to_scan(self.file_path)
            else:
                print("Error", f"Request failed with status code: {response.status_code}\n{response.text}")
        except Exception as e:
            print("Error", f"An error occurred: {str(e)}")

    def send_file_to_scan(self):
        try:
            with open(self.file_path, 'rb') as f:
                response = requests.post(
                    "https://malprob.io/api/scan/",
                    files={"file": f},
                    headers={"Authorization": f"Token {self.api_key}"},
                    timeout=120,
                )
            if response.status_code == 200:
                print("Success", "File sent for scanning successfully.")
            else:
                print("Error", f"Request failed with status code: {response.status_code}\n{response.text}")
        except Exception as e:
            print("Error", f"An error occurred: {str(e)}")

    def send_file_hash_to_rescan(self,file_hash):
        try:
            response = requests.post(
                "https://malprob.io/api/rescan/",
                json={"hash": file_hash},
                headers={
                    "Authorization": f"Token {self.api_key}"
                },
                timeout=120,
            )
            if response.status_code == 200:
                print("Success", "File hash sent for rescanning successfully.")
            else:
                print("Error", f"Request failed with status code: {response.status_code}\n{response.text}")
        except Exception as e:
            print("Error", f"An error occurred: {str(e)}")
        

class Responder:
    def __init__(self, file_path):
        self.file_path = file_path

    def delete_file(self):
        """ Deletes the file at the specified path. """
        try:
            os.remove(self.file_path)
            print(f"File {self.file_path} has been deleted.")
        except FileNotFoundError:
            print(f"No file found at {self.file_path} to delete.")
        except Exception as e:
            print(f"An error occurred: {e}")

    def move_file(self, destination):
        """ Moves the file to a new location. """
        try:
            shutil.move(self.file_path, destination)
            print(f"File has been moved to {destination}")
        except FileNotFoundError:
            print(f"No file found at {self.file_path} to move.")
        except Exception as e:
            print(f"An error occurred: {e}")

    def zip_with_password(self, zip_path,hashcode, password):
        """Zips the file with a password."""
        if os.path.exists(self.file_path):
            # Compression level: 5, 0 is no compression, 9 is best compression
            compression_level = 9
            pyminizip.compress(self.file_path, None, zip_path, password, compression_level)
            print(f"File has been zipped with password protection at {zip_path}.")
        else:
            print("File does not exist.")

    
