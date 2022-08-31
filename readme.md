# NT File Sharing Demo
## _File sharing demo backend using Flask python_


[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

This project requires Python version 3.8.0 minimum.
Please ensure your environment contains this version of python.
Run this command in your terminal to can check it ,

```sh
python --version
```

## Prerequisites
Firstly, you need "virtualenv" package from python to handle the environment.
Run this command,
```sh
pip install virtualenv
```
Next, clone this repository into your local machine
```sh
cd /to/your/desire/directory/
git clone https://github.com/narindech/nt_file_sharing_demo_backend.git
cd nt_file_sharing_demo_backend/
```
Then, run this command **(Make sure you are in nt_file_sharing_demo_backend folder already before execute this command.)**
```sh
python -m venv venv
```
You should see a new folder named "venv" in your current directory.

## Install dependencies
go to folder named "Scripts" using this command
```sh
cd nt_file_sharing_demo_backend/venv/Scripts
```

activate your virtual environment
```sh
.\activate
```

you should see "(venv)"" in front of your command line. That means your virtual environment is now activated.

Then, run this command to go back to your root folder and install dependencies as listed in file "requirements.txt"  **Make sure you are in nt_file_sharing_demo_backend folder already before execute this command and (venv) is already activated.**
```sh
cd ..
cd ..
pip install -r requirements.txt
```

## Run this app as a server
After all of dependencies are already installed. run this command to start your API server.
```sh
python main.py
```
