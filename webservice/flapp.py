import os
import sys
import json
import traceback

from flask import Flask
from flask import request, redirect

from . import utils

app = Flask(__name__)
utils.set_requests_verify(os.path.dirname(os.path.realpath(__file__)) + os.sep + 'gd-ca-bundle.crt')

@app.route('/')
def index_page():
    rurl = request.host_url+'configure'
    return redirect(rurl, code=302)

@app.route("/configure")
def handle_configure_bitbucket_app():
    print("Configure app service")
    config = utils.get_config()
    if config['bitbucket_app'].getboolean('setup_done'):
        print("Warning app aervice is already setup")
        file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/setup_done.html"
        with open(file_path, "r") as fd:
            fc = fd.read()
        return fc, 200, {'Content-Type': 'text/html'}

    file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/bitbucket_app_config.html"
    with open(file_path, "r") as fd:
        fc = fd.read()
    return fc, 200, {'Content-Type': 'text/html'}

@app.route("/save_config", methods=['POST'])
def handle_save_bitbucket_app_config():
    print("Save app service configuration")
    config = utils.get_config()
    if config['bitbucket_app'].getboolean('setup_done'):
        print("Warning app service is already setup")
        file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/setup_done.html"
        with open(file_path, "r") as fd:
            fc = fd.read()
        return fc, 200, {'Content-Type': 'text/html'}

    # update configuration
    tw_handle = request.values.get('tw_handle')
    tw_api_key = request.values.get('tw_api_key')
    tw_instance = request.values.get('tw_instance')
    sast_enabled = request.values.get('sast_enabled')
    iac_enabled = request.values.get('iac_enabled')
    secrets_enabled = request.values.get('secrets_enabled')
    code_sharing_enabled = request.values.get('code_sharing_enabled')
    tw_bb_access_token = request.values.get('tw_bb_access_token')
    tw_user_tags = request.values.get('tw_user_tags')
    config['threatworx']['handle'] = tw_handle
    config['threatworx']['token'] = tw_api_key
    config['threatworx']['instance'] = tw_instance
    config['bitbucket_app']['bitbucket_access_token'] = tw_bb_access_token
    config['bitbucket_app']['user_tags'] = tw_user_tags
    config['bitbucket_app']['sast_checks_enabled'] = 'true' if sast_enabled == 'yes' else 'false'
    config['bitbucket_app']['iac_checks_enabled'] = 'true' if iac_enabled == 'yes' else 'false'
    config['bitbucket_app']['secrets_checks_enabled'] = 'true' if secrets_enabled == 'yes' else 'false'
    config['bitbucket_app']['code_sharing'] = 'true' if code_sharing_enabled == 'yes' else 'false'
    config['bitbucket_app']['setup_done'] = 'true'
    utils.write_config(config)
    config = utils.get_config(True)

    file_path = os.path.dirname(os.path.realpath(__file__)) + "/../templates/success.html"
    with open(file_path, "r") as fd:
        fc = fd.read()
    return fc, 200, {'Content-Type': 'text/html'}

@app.route("/webhook", methods=['POST'])
def webhook():
    try:
        bitbucket_token = None
        config = utils.get_config()

        #base_discovery_enabled = config['bitbucket_app'].getboolean('base_discovery_enabled')
        event = json.loads(request.data)
        if 'push' in event.keys():
            utils.process_push_request(event)

        return "", 200, {'Content-Type': 'text/plain'}
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return "Internal Server Error", 500, {'Content-Type': 'text/plain'}

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int("80"))
