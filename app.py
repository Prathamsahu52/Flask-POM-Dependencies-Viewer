from flask import Flask, flash
from flask_github import GitHub
from flask import Flask, redirect, url_for, session, request, abort, render_template
from flask_login import LoginManager, UserMixin, login_user, logout_user,current_user
from datetime import date
from time import strftime, localtime
from colorama import Fore, Style
import secrets
from dotenv import load_dotenv
import os
from urllib.parse import urlencode
import requests
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
import base64
import json



load_dotenv()

status_color = {
    'INFO': Fore.GREEN,
    'ERROR': Fore.RED,
    'WARNING': Fore.YELLOW,
    'DEBUG': Fore.CYAN,
    'CRITICAL': Fore.MAGENTA
}



app = Flask(__name__)

app.config['OAUTH2_PROVIDERS'] = {
    'github': {
        'client_id': '4dadf91f2e782fe3e18a',
        'client_secret': '89922627e347c52d274daee182818119d65cc7ef',
        'authorize_url': 'https://github.com/login/oauth/authorize',
        'token_url': 'https://github.com/login/oauth/access_token',
        'userinfo': {
            'url': 'https://api.github.com/user/emails',
            'email': lambda json: json[0]['email'],
        },
        'scopes': ['user:email'],
    },
}


def display(status, data, start='', end='\n'):
    print(f"{start}{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {strftime('%H:%M:%S', localtime())}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}", end=end)


def parse_repo(repo_url, auth_token):
    repo_url = repo_url.strip()
    headers = {"Authorization": auth_token}

    owner = repo_url.split('/')[3]
    repo = repo_url.split('/')[4]
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/main?recursive=1"
    display('INFO', f"URL: {url}")


    file_data_res = requests.get(url, headers=headers)
    display('INFO', f"AUTH TOKEN: {auth_token}")
    file_data_json = file_data_res.json()
    file_tree = file_data_json['tree']
    found = False
    dependencies = {}
    for file in file_tree:
        if(file['path'].split("/")[-1] == 'pom.xml'):
            found = True
            display('INFO', f"Found the pom.xml file in the repository: {repo_url}/{file['path']}")
            file_path = file['path']
            dependency = get_dependencies_from_pom(file_path, repo_url, auth_token)
            dependencies[file['path']] = dependency

    if(found == False):
        display('ERROR', f"The pom.xml file was not found in the repository: {repo_url}")
        return 'Pom file not found'
    else:
        return dependencies
            

def get_dependencies_from_pom(file_path, repo_url, auth_token):
    display('INFO', f"Getting the dependencies from the pom.xml file...")
    headers = {"Authorization": auth_token}

    owner = repo_url.split('/')[3]
    repo = repo_url.split('/')[4]
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
    display('INFO', f"URL: {url}")


    file_data_res = requests.get(url, headers=headers)
    display('INFO', f"AUTH TOKEN: {auth_token}")


    if file_data_res.status_code != 200:
        display('ERROR', f"Error fetching the pom.xml file: {file_path}")
        return 'Pom file not found'
    file_data = file_data_res.json()
    file_content = file_data['content']
    
    # Decode the base64 encoded content
    file_content = base64.b64decode(file_content).decode('utf-8')
    # display('INFO', f"File content: {file_content}")
    dependencies = []
    try:
        root = ET.fromstring(file_content)
        for dependency in root.iter('{http://maven.apache.org/POM/4.0.0}dependency'):
            group_id = dependency.find('{http://maven.apache.org/POM/4.0.0}groupId').text
            artifact_id = dependency.find('{http://maven.apache.org/POM/4.0.0}artifactId').text
            # display('INFO', f"Artifact ID: {artifact_id}")
            if(dependency.find('{http://maven.apache.org/POM/4.0.0}version') is not None):
                version = dependency.find('{http://maven.apache.org/POM/4.0.0}version').text
            else:
                version = 'Not specified'
            dependencies.append((group_id, artifact_id, version))
        display('INFO', f"Found {len(dependencies)} dependencies in the pom.xml file.")
        return dependencies
    
    except FileNotFoundError:
        display('ERROR', f"The pom.xml file was not found in the repository: {file_path}")
    except ET.ParseError:
        display('ERROR', f"Error parsing the pom.xml file: {file_path}")

    return 'Pom file not found'

def get_user_data(access_token: str) -> dict:
    """Obtain the user data from github.
    Given the access token issued out by GitHub, this method should give back the
    user data
    Parameters
    ----------
    request_token: str
        A string representing the request token issued out by github
    Throws
    ------
    ValueError:
        if access_token is empty or not a string
    Returns
    -------
    user_data: dict
        A dictionary with the users data:
        {
            "avatar_url": "https://avatars.githubusercontent.com/u/60782180?v=4",
            "bio": "Founder @oryksrobotics. I design and build robots for the logistics and supply chain industry.",
            "blog": "",
            "company": "oryks robotics",
            "created_at": "2020-02-07T12:49:50Z",
            "email": null,
            "events_url": "https://api.github.com/users/lyleokoth/events{/privacy}",
            "followers": 2,
            "followers_url": "https://api.github.com/users/lyleokoth/followers",
            "following": 8,
            "following_url": "https://api.github.com/users/lyleokoth/following{/other_user}",
            "gists_url": "https://api.github.com/users/lyleokoth/gists{/gist_id}",
            "gravatar_id": "",
            "hireable": null,
            "html_url": "https://github.com/lyleokoth",
            "id": 60782180,
            "location": "Nairobi, Kenya",
            "login": "lyleokoth",
            "name": null,
            "node_id": "MDQ6VXNlcjYwNzgyMTgw",
            "organizations_url": "https://api.github.com/users/lyleokoth/orgs",
            "public_gists": 0,
            "public_repos": 79,
            "received_events_url": "https://api.github.com/users/lyleokoth/received_events",
            "repos_url": "https://api.github.com/users/lyleokoth/repos",
            "site_admin": false,
            "starred_url": "https://api.github.com/users/lyleokoth/starred{/owner}{/repo}",
            "subscriptions_url": "https://api.github.com/users/lyleokoth/subscriptions",
            "twitter_username": "lylethedesigner",
            "type": "User",
            "updated_at": "2022-03-21T11:00:43Z",
            "url": "https://api.github.com/users/lyleokoth"
        }
    """
    if not access_token:
        raise ValueError('The request token has to be supplied!')
    if not isinstance(access_token, str):
        raise ValueError('The request token has to be a string!')

    access_token = 'token ' + access_token
    url = 'https://api.github.com/user'
    headers = {"Authorization": access_token}

    resp = requests.get(url=url, headers=headers)

    userData = resp.json()

    return userData


@app.route('/')
def index():
    provider_data = app.config['OAUTH2_PROVIDERS']['github']
    print(provider_data['client_id'])


    return render_template('index.html')
    

@app.route('/login')
def login():
    provider_data = app.config['OAUTH2_PROVIDERS']['github']
    qs = urlencode({
        'client_id': provider_data['client_id'],
        'redirect_uri': url_for('authorized', _external=True),
        'response_type': 'code',
        'scope': ' '.join(provider_data['scopes']),
    })
    # redirect the user to the OAuth2 provider authorization URL
    return redirect(provider_data['authorize_url'] + '?' + qs)

@app.route('/search')
def search_for_pom():
    display('INFO', 'Searching for pom')
    url = request.args.get('url')
    auth_token = request.args.get('auth_token')

    if not url:
        display('ERROR', 'URL not provided')
        return 'URL not provided'
    else:
        display('INFO', f'URL provided: {url}')
        display('DEBUG', f'Auth token provided: {auth_token}')
        dependencies = parse_repo(url, auth_token)
        if(dependencies == 'Pom file not found'):
            return 'Pom file not found'
        else:
            return render_template('pomlist.html', Dependencies=dependencies)
    # display('DEBUG', url)
    # return 'URL provided'



@app.route('/github-callback')
def authorized():
    display('INFO', 'Authorized')
    if 'code' not in request.args:
        abort(401)
    provider_data = app.config['OAUTH2_PROVIDERS']['github']
    response = requests.post(provider_data['token_url'], data={
        'client_id': provider_data['client_id'],
        'client_secret': provider_data['client_secret'],
        'code': request.args['code'],
        'grant_type': 'authorization_code',
        'redirect_uri': url_for('authorized', _external=True),
    }, headers={'Accept': 'application/json'})

    if response.status_code != 200:
        abort(401)
    oauth2_token = response.json().get('access_token')
    if not oauth2_token:
        abort(401)
    print(oauth2_token)
    # use the access token to get the user's email address
    response = requests.get(provider_data['userinfo']['url'], headers={
        'Authorization': 'Bearer ' + oauth2_token,
        'Accept': 'application/json',
    })
    if response.status_code != 200:
        abort(401)
    email = provider_data['userinfo']['email'](response.json())
    print(email)
    user_data = get_user_data(oauth2_token)
    print(user_data)
    print(user_data['repos_url'])
    response = requests.get(user_data['repos_url'])
    repos = response.json()

    return render_template('success.html', repos=repos, user_data=user_data, auth_token=oauth2_token)



if __name__ == '__main__':
    app.run(debug=True)

