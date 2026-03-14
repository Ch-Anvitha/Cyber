from dotenv import load_dotenv
load_dotenv()  # Load .env file before anything else

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from urllib.parse import urlparse
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from scanner import run_full_scan
from report_generator import generate_pdf_report

app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')
CORS(app)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url  = data.get('url', '').strip().rstrip('/')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Add https:// if missing
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    # Basic validation
    hostname = urlparse(url).hostname or ''
    if '.' not in hostname:
        return jsonify({'error': 'Please enter a valid website URL (e.g. https://yoursite.com)'}), 400

    try:
        result = run_full_scan(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/generate-report', methods=['POST'])
def generate_report():
    data = request.get_json()
    try:
        reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
        filename    = generate_pdf_report(data, reports_dir)
        if filename:
            return jsonify({'filename': filename, 'url': f'/report/{filename}'})
        return jsonify({'error': 'PDF generation failed - install reportlab'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/report/<path:filename>')
def download_report(filename):
    reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
    return send_from_directory(reports_dir, filename, as_attachment=True)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url  = data.get('url', '').strip().rstrip('/')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # If user typed multiple URLs, take only the first one
    url = url.split()[0]  # ← add this line

    # Add https:// if missing
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    hostname = urlparse(url).hostname or ''
    if '.' not in hostname:
        return jsonify({'error': 'Please enter one valid website URL (e.g. https://yoursite.com)'}), 400

    try:
        result = run_full_scan(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)