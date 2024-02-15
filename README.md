# Flask POM Dependencies Viewer

This Flask application provides a web interface for viewing Maven project dependencies defined in `pom.xml` files within a specified github repository. It first authenticates using github's Oauth, then scans the repo for `pom.xml` files, extracts dependencies from each file, and displays them in an organized manner.


## Getting Started

### Prerequisites

- Python 3.x
- Flask
- An environment where you can run Flask applications (e.g., Linux/Windows/MacOS)
### Setup a python virtualenv

```
python3 -m venv parserenv
source parserenv/bin/activate
```
### Installation

1. Clone the repository to your local machine:

```
git clone https://github.com/yourusername/flask-pom-viewer.git
cd github-pom-dependency-viewer
```

2. Install the required Python packages
   
```
pip install -r requirements.txt
```

3. Configuration
Set the environment and run
   
```
export FLASK_APP = app.py
flask run
```