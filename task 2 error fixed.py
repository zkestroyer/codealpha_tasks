from flask import Flask, request, send_from_directory, abort
from werkzeug.utils import secure_filename
import os
import magic  # install python-magic
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Rate limiting
limiter = Limiter(get_remote_address, app=app)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
@limiter.limit("5 per minute")
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # MIME type checking
        file_bytes = file.read()
        file_mime = magic.from_buffer(file_bytes, mime=True)
        if not file_mime.startswith('image/'):
            return 'Invalid file type', 400
        with open(filepath, 'wb') as f:
            f.write(file_bytes)

        return 'File uploaded successfully'
    return 'Invalid file', 400

@app.route('/files/<filename>')
@limiter.limit("10 per minute")
def get_file(filename):
    filename = secure_filename(filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.isfile(filepath):
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run()
