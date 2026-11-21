from flask import Blueprint, request, send_from_directory, abort
import re

uploads_api = Blueprint('uploads', __name__)

# D2 fix: restrict uploads to plain image names and serve only from the
# uploads directory to prevent path traversal.
SAFE_NAME = re.compile(r'^[A-Za-z0-9._-]+\.(jpg|jpeg|png|gif|webp)$')

@uploads_api.route('/')
def get_upload():
   name = request.args.get("name", "")
   if not SAFE_NAME.match(name):
      abort(404)
   return send_from_directory('uploads', name)