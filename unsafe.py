import os
import flask

app = flask.Flask(__name__)

@app.route('/ping')
def ping():
    # VULNERABILITY: OS Command Injection
    # CodeQL should catch this easily as it requires no compilation.
    address = flask.request.args.get('address')
    cmd = "ping -c 4 " + address
    os.system(cmd)
    return "Pinging..."

@app.route('/exec')
def exec_cmd():
    # Another explicit one
    cmd = flask.request.args.get('cmd')
    os.popen(cmd)
    return "Executed"

# GHAS Trigger: 1770888506