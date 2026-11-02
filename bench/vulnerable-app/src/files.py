import os
import pickle
import hashlib
from flask import Flask, request

app = Flask(__name__)

@app.route("/download")
def download():
    name = request.args.get("file")
    return open("/srv/files/" + name).read()

@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))

def store_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

@app.route("/run")
def run():
    os.system("convert " + request.args.get("img"))
    return "ok"
