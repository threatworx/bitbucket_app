import sys
import os
import subprocess
import configparser
import requests
import time
import uuid
import tempfile
import json
from filelock import FileLock

config = None
GoDaddyCABundle = True
CONFIG_FILE = '/opt/tw_bitbucket_app/config/config.ini'

def get_config(force_read = False):
    global config
    if force_read == False and config is not None:
        return config
    global CONFIG_FILE
    env_config_path = os.environ.get("TW_BITBUCKET_APP_CONFIG")
    if env_config_path is None:
        print("Warning environment variable [TW_BITBUCKET_APP_CONFIG] is not specified. Falling back to default path for config file [/opt/tw_bitbucket_app/config/config.ini]")
    elif os.path.isdir(env_config_path) == False:
        print("Error specified path [%s] in environment varliable [TW_BITBUCKET_APP_CONFIG] not found" % env_config_path)
        print("Error unable to start server...")
        sys.exit(1)
    else:
        CONFIG_FILE = env_config_path + os.path.sep + "config.ini"

    if os.path.isfile(CONFIG_FILE) == False:
        print("Error configuration file [%s] not found" % CONFIG_FILE)
        sys.exit(1)
    config = configparser.ConfigParser()
    lock = FileLock(CONFIG_FILE + ".lock")
    with lock:
        config.read(CONFIG_FILE)
    return config

def write_config(config):
    lock = FileLock(CONFIG_FILE + ".lock")
    with lock:
        with open(CONFIG_FILE, 'w') as fd:
            config.write(fd)

def update_access_token_cache(at_index, access_token):
    lock = FileLock(CONFIG_FILE + ".lock")
    with lock:
        config = get_config(True)
        config['bitbucket_tokens_cache'][at_index] = access_token
        write_config(config)

def check_access_token(repo_url, bitbucket_access_token):
    config = get_config()
    bitbucket_user = config['bitbucket_app']['bitbucket_user']
    updated_repo_url = "https://" + bitbucket_user + ":" + bitbucket_access_token + '@' + repo_url.split('//')[1]

    # Run base asset discovery
    git_cmd = "git ls-remote %s" % updated_repo_url
    dev_null_device = open(os.devnull, "w")
    try:
        process = subprocess.run([git_cmd], stdout=dev_null_device, stderr=dev_null_device, shell=True)
        if process.returncode == 0:
            return True
        return False
    except subprocess.CalledProcessError as e:
        print("Error running [git ls-remote] command")
        print(e)
        return False

def get_access_token_bruteforce(repo_url):
    config = get_config()
    bb_tokens_dict = dict(config['bitbucket_tokens'])
    for key in list(bb_tokens_dict.keys()):
        if "token_name_" in key:
            tv = key.replace("token_name_", "token_value_")
            access_token = bb_tokens_dict[tv]
            if check_access_token(repo_url, access_token):
                return access_token
    return None

def get_access_token(repo_url, at_index):
    config = get_config()
    if not config.has_section('bitbucket_tokens_cache'):
        config.add_section('bitbucket_tokens_cache')
        write_config(config)

    at_cache = dict(config['bitbucket_tokens_cache'])
    access_token = at_cache.get(at_index)
    if access_token is None:
        access_token = get_access_token_bruteforce(repo_url)
        if access_token is None:
            # This is bad, seems like there is no access token corresponding to this repo_url
            print("Error unable to find working access token for repo [%s]" % repo_url)
            return None
        update_access_token_cache(at_index, access_token)
        return access_token

    # It is possible that the cached access token is stale i.e. it has been updated
    if check_access_token(repo_url, access_token):
        return access_token
    else:
        access_token = get_access_token_bruteforce(repo_url)
        if access_token is None:
            # This is bad, seems like there is no access token corresponding to this repo_url
            print("Error unable to find working access token for repo [%s]" % repo_url)
            return None
        update_access_token_cache(at_index, access_token)
        return access_token

def discover_repo(repo_url, asset_id, branch, accesstoken_index):
    config = get_config()

    bitbucket_user = config['bitbucket_app']['bitbucket_user']
    bitbucket_access_token = get_access_token(repo_url, accesstoken_index)
    if bitbucket_access_token is None:
        print("Error unable to discover repo [%s] due to absence of valid access token" % repo_url)
        return
    updated_repo_url = "https://" + bitbucket_user + ":" + bitbucket_access_token + '@' + repo_url.split('//')[1]

    handle = config['threatworx']['handle']
    token = config['threatworx']['token']
    instance = config['threatworx']['instance']

    base_discovery = True
    sast_checks_enabled = config['bitbucket_app'].getboolean('sast_checks_enabled')
    iac_checks_enabled = config['bitbucket_app'].getboolean('iac_checks_enabled')
    secrets_checks_enabled = config['bitbucket_app'].getboolean('secrets_checks_enabled')
    code_sharing = config['bitbucket_app'].getboolean('code_sharing')
    ssl_verification = config['threatworx'].getboolean('ssl_verification', fallback=True)
    insecure = "" if ssl_verification else "--insecure"
    dev_null_device = open(os.devnull, "w")
    org = repo_url.split('//')[1].split('/')[1]
    tags = config['bitbucket_app'].get('user_tags')
    tags = '' if tags is None else tags.strip()
    tags = tags.split(',')
    ptags = "--tag '%s'" % (org)
    for tag in tags:
        tag = tag.strip()
        if tag == "":
            continue # skip empty tags
        ptags = "%s --tag '%s'" % (ptags, tag)

    if base_discovery:
        twigs_cmd = "twigs -v %s --handle '%s' --token '%s' --instance '%s' %s --create_empty_asset --apply_policy SYNC_SCAN --run_id bitbucket_app repo --repo '%s' --assetid '%s' --assetname '%s'" % (insecure, handle, token, instance, ptags, updated_repo_url, asset_id, asset_id)
        print("Starting asset discovery & scan for repo [%s] and branch [%s]" % (repo_url, branch))
        if branch is not None:
            twigs_cmd = twigs_cmd + " --branch '%s'" % branch

        # Run base asset discovery
        try:
            out = subprocess.check_output([twigs_cmd], stderr=dev_null_device, shell=True)
            print("Base asset discovery completed")
        except subprocess.CalledProcessError as e:
            print("Error running twigs discovery")
            print(e)
            return False

    # Perform IaC checks if enabled and specified to be run
    if iac_checks_enabled:
        twigs_cmd = "twigs -v %s --handle '%s' --token '%s' --instance '%s' %s --create_empty_asset --no_scan --run_id bitbucket_app repo --repo '%s' --assetid '%s' --assetname '%s' --iac_checks" % (insecure, handle, token, instance, ptags, updated_repo_url, asset_id, asset_id)
        if branch is not None:
            twigs_cmd = twigs_cmd + " --branch '%s'" % branch
        if code_sharing == False:
            twigs_cmd = twigs_cmd + " --no_code"
        print("Running IaC checks for repo [%s] and branch [%s]" % (repo_url, branch))
        try:
            out = subprocess.check_output([twigs_cmd], stderr=dev_null_device, shell=True)
            print("IaC checks completed")
        except subprocess.CalledProcessError as e:
            print("Error running twigs IaC checks")
            print(e)
            return False
        
    # Perform secrets checks if enabled
    if secrets_checks_enabled:
        twigs_cmd = "twigs -v %s --handle '%s' --token '%s' --instance '%s' %s --create_empty_asset --no_scan --run_id bitbucket_app repo --repo '%s' --assetid '%s' --assetname '%s' --secrets_scan" % (insecure, handle, token, instance, ptags, updated_repo_url, asset_id, asset_id)
        if branch is not None:
            twigs_cmd = twigs_cmd + " --branch '%s'" % branch
        if code_sharing == False:
            twigs_cmd = twigs_cmd + " --no_code"
        print("Running secrets checks for repo [%s] and branch [%s]" % (repo_url, branch))
        try:
            out = subprocess.check_output([twigs_cmd], stderr=dev_null_device, shell=True)
            print("Secrets checks completed")
        except subprocess.CalledProcessError as e:
            print("Error running twigs secrets checks")
            print(e)
            return False

    # Perform sast checks if enabled
    if sast_checks_enabled:
        twigs_cmd = "twigs -v %s --handle '%s' --token '%s' --instance '%s' %s --create_empty_asset --no_scan --run_id bitbucket_app repo --repo '%s' --assetid '%s' --assetname '%s' --sast" % (insecure, handle, token, instance, ptags, updated_repo_url, asset_id, asset_id)
        if branch is not None:
            twigs_cmd = twigs_cmd + " --branch '%s'" % branch
        if code_sharing == False:
            twigs_cmd = twigs_cmd + " --no_code"
        print("Running SAST checks for repo [%s] and branch [%s]" % (repo_url, branch))
        try:
            out = subprocess.check_output([twigs_cmd], stderr=dev_null_device, shell=True)
            print("SAST completed")
        except subprocess.CalledProcessError as e:
            print("Error running twigs SAST checks")
            print(e)
            return False

    return True

def set_requests_verify(verify):
    global GoDaddyCABundle
    GoDaddyCABundle = verify

def get_requests_verify():
    global GoDaddyCABundle
    config = get_config()
    ssl_verification = config['threatworx'].getboolean('ssl_verification', fallback=True)
    if ssl_verification:
        return GoDaddyCABundle
    else:
        return False

def launch_request_handler_process(python_script_name, event_data):
    temp_json_file = tempfile.NamedTemporaryFile(mode='w', prefix='tw-', suffix='_ed.json', delete=False)
    temp_json_file_name = temp_json_file.name
    json.dump(event_data, temp_json_file)
    temp_json_file.close()
    base_path = os.path.dirname(os.path.realpath(__file__))
    cmd = base_path + os.sep + python_script_name + ' -f ' + temp_json_file_name
    #print(cmd)
    proc = subprocess.Popen([cmd], shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)

def process_push_request(event_data):
    launch_request_handler_process('push_request_handler', event_data)
