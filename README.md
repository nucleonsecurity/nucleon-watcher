# Nucleon-Watcher
 
Nucleon watcher is a File detection and response tool that helps you to find malicious files inside a specific directory. Using Nucleon malprob API, Nucleon watcher scans the files and returns the result to the user. Nucleon watcher is a command line tool that can be used in different platform. 

<!-- # Requirements -->
<!-- - Python 3.6 or higher -->
<!-- -  -->
# Installation
## using a virtual environment
### Windows

```bash
python -m venv watcher_env
```
```bash
watcher_env\Scripts\activate
```
```bash
pip install -r requirements.txt
```
### Linux and MacOS

```bash
python3 -m venv watcher_env
```
```bash
source watcher_env/bin/activate
```
```bash
pip install -r requirements.txt
```


## using docker
To do
# Getting Started
## Help 
```bash
python Watcher.py --help
```
## Usage
to run the watcher on a specific folder :
```bash
python Watcher.py --watched_directory .\watched_directory
```