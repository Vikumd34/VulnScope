from flask import Blueprint, Response, current_app
from flask_login import login_required
import os
from utils.logger import LOG_PATH

admin_bp = Blueprint('admin', __name__)


def tail(filepath, lines=200):
    try:
        with open(filepath, 'rb') as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            size = 1024
            data = b''
            while end > 0 and data.count(b"\n") <= lines:
                start = max(0, end - size)
                f.seek(start)
                chunk = f.read(end - start)
                data = chunk + data
                end = start
                size *= 2
            return b"\n".join(data.splitlines()[-lines:]).decode('utf-8', errors='replace')
    except Exception:
        return ''


@admin_bp.route('/admin/logs')
@login_required
def view_logs():
    log_path = LOG_PATH
    if not os.path.exists(log_path):
        return Response('No logs found', mimetype='text/plain')
    content = tail(log_path, lines=200)
    return Response(content, mimetype='text/plain')
