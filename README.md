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

# Getting Started

## Get your API key 
1. Go to [Nucleon Malprob](https://malprob.io/).
2. Create an account [Sign-up](https://malprob.io/signup). 
3. Get your API key from [Your account](https://malprob.io/account).
4. Create a file named `.env` in the root directory of the project.
5. Plug your api key in the `.env` file:
```bash
malprob_key="your_api_key"
```
## Help 
```bash
python src/watcher.py --help
```
## Usage
to run the watcher on a specific folder :
```bash
python src/watcher.py --watched_directory watched_directory
```