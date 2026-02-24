from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/ping')
def ping():
    hostname = request.args.get('hostname')
    # VULNERABILITY: Command Injection
    # User input is passed directly to the shell.
    os.system("ping -c 1 " + hostname)
    return "Pinged"

if __name__ == '__main__':
    app.run()

# GHAS Trigger: 1771939286