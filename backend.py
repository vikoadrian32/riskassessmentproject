from flask import Flask, render_template, request, redirect, url_for, jsonify
import mysql.connector
import requests  # Menggunakan requests untuk API VirusTotal
import base64  # Untuk mengubah URL menjadi base64
from dash import Dash, dcc, html
import plotly.express as px
import pandas as pd
from pymisp import PyMISP  # Menggunakan PyMISP untuk integrasi MISP

# Flask app
app = Flask(__name__)

# API Key VirusTotal (ganti dengan API Key Anda)
API_KEY = '732f52763f6495a40edf2edff2787fb6dd1d04a5b7761361b8d64233aac7f9eb'
VT_API_URL = 'https://www.virustotal.com/api/v3/'

# Koneksi ke database MySQL
conn = mysql.connector.connect(
    host="127.0.0.1",
    port="3306",
    user="root",
    password="herosenin123",
    database="riskassessment"
)
cursor = conn.cursor()

# Fungsi untuk mengambil ancaman dari VirusTotal menggunakan URL atau hash
def get_virustotal_threats(indicator):
    headers = {
        'x-apikey': API_KEY
    }

    # Cek apakah indikator adalah URL atau hash
    if indicator.startswith('http'):  # URL
        # Encode URL to Base64
        base64_url = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        response = requests.get(f'{VT_API_URL}urls/{base64_url}', headers=headers)
    else:  # Hash
        response = requests.get(f'{VT_API_URL}files/{indicator}', headers=headers)

    if response.status_code == 200:
        return response.json()  # Mengembalikan data JSON yang didapat dari VirusTotal
    else:
        return {'error': 'Unable to fetch data from VirusTotal'}

# Dashboard menggunakan Dash untuk Visualisasi
dash_app = Dash(__name__, server=app, url_base_pathname='/dashboard/')
dash_app.layout = html.Div([
    html.H1('Risk Assessment Dashboard'),
    dcc.Graph(id='heatmap'),
    dcc.Graph(id='category-pie')
])

# Route Home
@app.route('/')
def home():
    return render_template('home.html')

# Route untuk Form Assessment
@app.route('/assessment')
def form():
    return render_template('assessment.html')

# Route untuk Form URL Input
@app.route('/virustotal', methods=['GET', 'POST'])
def virustotal():
    if request.method == 'POST':
        url = request.form['url']
        # Ambil data ancaman dari VirusTotal untuk URL yang dimasukkan
        threats = get_virustotal_threats(url)
        return render_template('virustotal.html', threats=threats, url=url)
    return render_template('virustotal.html')

# Endpoint untuk mengambil data ancaman dalam format JSON (untuk API)
@app.route('/api/threats', methods=['GET'])
def api_threats():
    # Ambil indikator dari query parameter
    indicator = request.args.get('indicator', default='', type=str)
    if indicator:
        threats = get_virustotal_threats(indicator)
        return jsonify(threats)
    return jsonify({'error': 'Indicator parameter is missing or invalid'})


# Route untuk Submit Data Assessment
@app.route('/submit', methods=['POST'])
def submit():
    # Form submission logic here
    ...

# Route untuk Menampilkan Hasil Assessment
@app.route('/result')
def result():
    assessment_id = request.args.get('assessment_id', type=int)
    if not assessment_id:
        return "Invalid assessment ID."

    cursor.execute("""
        SELECT likelihood, impact, overall_risk_level
        FROM Risk_Analysis
        WHERE assessment_id = %s
    """, (assessment_id,))

    data = cursor.fetchall()

    if not data:
        return "No data available for this assessment ID."

    df = pd.DataFrame(data, columns=["Likelihood", "Impact", "Risk Level"])
    heatmap_fig = px.scatter(df, x='Impact', y='Likelihood', color='Risk Level', title="Risk Heatmap")
    category_pie = px.pie(df, names='Risk Level', title="Distribution of Risks by Risk Level")

    return render_template('result.html', heatmap_fig=heatmap_fig.to_html(), category_pie=category_pie.to_html())

# Menjalankan Flask
if __name__ == '__main__':
    app.run(debug=True)
