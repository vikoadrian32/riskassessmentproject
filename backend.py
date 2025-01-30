import io
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file
import mysql.connector
import requests
import base64
from dash import Dash, dcc, html
import plotly.express as px
import pandas as pd
import plotly.io as pio
import os
from dotenv import load_dotenv
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.units import inch
from PIL import Image as PILImage
from io import BytesIO
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

load_dotenv()

# Flask app initialization
app = Flask(__name__)


# Add cache control headers
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


# VirusTotal Configuration
API_KEY = os.environ.get('API_KEY')
VT_API_URL = os.environ.get('VT_API_URL')

# MySQL Connection
conn = mysql.connector.connect(
    host="127.0.0.1",
    port="3306",
    user="root",
    password="",
    database="riskassessment"
)
cursor = conn.cursor()

# Risk mappings
likelihood_mapping = {
    'very low': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'very high': 4
}

impact_mapping = {
    'negligible': 0,
    'limited': 1,
    'serious': 2,
    'major': 3,
    'catastrophic': 4
}


def get_virustotal_threats(indicator):
    headers = {
        'x-apikey': API_KEY
    }

    if indicator.startswith('http'):
        base64_url = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        response = requests.get(f'{VT_API_URL}urls/{base64_url}', headers=headers)
    else:
        response = requests.get(f'{VT_API_URL}files/{indicator}', headers=headers)

    return response.json() if response.status_code == 200 else {'error': 'Unable to fetch data from VirusTotal'}


# Dash app initialization with improved configuration
dash_app = Dash(
    __name__,
    server=app,
    url_base_pathname='/dashboard/',
    assets_folder='assets',
    suppress_callback_exceptions=True,
    meta_tags=[
        {"name": "viewport", "content": "width=device-width, initial-scale=1"}
    ]
)

# Improved responsive layout
dash_app.layout = html.Div([
    html.Div([
        html.H1('Risk Assessment Dashboard',
                style={
                    'textAlign': 'center',
                    'marginBottom': '30px',
                    'color': '#2c3e50',
                    'fontFamily': 'Arial, sans-serif'
                }),
        html.Div([
            dcc.Graph(
                id='heatmap',
                style={
                    'width': '100%',
                    'height': '60vh',
                    'marginBottom': '30px'
                }
            ),
        ]),
        html.Div([
            dcc.Graph(
                id='category-pie',
                style={
                    'width': '100%',
                    'height': '60vh'
                }
            ),
        ])
    ], style={
        'padding': '20px',
        'maxWidth': '1200px',
        'margin': '0 auto',
        'backgroundColor': '#ffffff',
        'boxShadow': '0 0 10px rgba(0,0,0,0.1)',
        'borderRadius': '8px'
    })
])


@app.route('/generate_pdf', methods=['POST'])
def generate_pdf():
    try:
        # Ambil data dari database
        cursor.execute("""
            SELECT a.name, a.purpose, a.scope, a.owner, a.department,
                   r.assets, r.threat_sources, r.threat_events, r.vulnerabilities,
                   ra.likelihood, ra.impact, ra.overall_risk_level,
                   rt.mitigation_strategy, rt.mitigation_steps, rt.timeline
            FROM Assessments a
            JOIN Risks r ON a.id = r.assessment_id
            JOIN Risk_Analysis ra ON a.id = ra.assessment_id
            JOIN Risk_Treatment rt ON a.id = rt.assessment_id
        """)
        assessments = cursor.fetchall()

        # Ambil data untuk risk heatmap dan distribution
        cursor.execute("""
            SELECT likelihood, impact, overall_risk_level 
            FROM Risk_Analysis
        """)
        risk_data = cursor.fetchall()

        # Buat DataFrame untuk visualisasi
        df_risk = pd.DataFrame(risk_data, columns=['Likelihood', 'Impact', 'Risk Level'])

        # Fungsi untuk membuat Risk Heatmap
        def create_risk_heatmap(df):
            plt.figure(figsize=(10, 8))
            pivot_table = pd.pivot_table(df, values='Risk Level', 
                                         index='Likelihood', 
                                         columns='Impact', 
                                         aggfunc='count')
            
            sns.heatmap(pivot_table, annot=True, cmap='YlOrRd', fmt='g')
            plt.title('Risk Heatmap')
            plt.tight_layout()
            
            # Simpan plot ke buffer
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png')
            buffer.seek(0)
            plt.close()
            return buffer

        # Fungsi untuk membuat Risk Distribution
        def create_risk_distribution(df):
            plt.figure(figsize=(10, 6))
            df['Risk Level'].value_counts().plot(kind='bar')
            plt.title('Risk Distribution')
            plt.xlabel('Risk Level')
            plt.ylabel('Number of Risks')
            plt.tight_layout()
            
            # Simpan plot ke buffer
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png')
            buffer.seek(0)
            plt.close()
            return buffer

        # Buat PDF di memory
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Tambahkan judul
        title = Paragraph("Comprehensive Risk Assessment Report", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 12))

        # Proses setiap assessment
        for assessment in assessments:
            story.append(Paragraph(f"Project Name: {assessment[0]}", styles['Heading2']))
            story.append(Paragraph(f"Purpose: {assessment[1]}", styles['Normal']))
            story.append(Paragraph(f"Scope: {assessment[2]}", styles['Normal']))
            story.append(Paragraph(f"Owner: {assessment[3]}", styles['Normal']))
            story.append(Paragraph(f"Department: {assessment[4]}", styles['Normal']))
            story.append(Spacer(1, 12))

            # Tambahkan detail risiko
            story.append(Paragraph("Risk Details:", styles['Heading3']))
            story.append(Paragraph(f"Assets: {assessment[5]}", styles['Normal']))
            story.append(Paragraph(f"Threat Sources: {assessment[6]}", styles['Normal']))
            story.append(Paragraph(f"Threat Events: {assessment[7]}", styles['Normal']))
            story.append(Paragraph(f"Vulnerabilities: {assessment[8]}", styles['Normal']))
            story.append(Spacer(1, 12))

            # Tambahkan analisis risiko
            story.append(Paragraph("Risk Analysis:", styles['Heading3']))
            story.append(Paragraph(f"Likelihood: {assessment[9]}", styles['Normal']))
            story.append(Paragraph(f"Impact: {assessment[10]}", styles['Normal']))
            story.append(Paragraph(f"Overall Risk Level: {assessment[11]}", styles['Normal']))
            story.append(Spacer(1, 12))

            # Tambahkan strategi mitigasi
            story.append(Paragraph("Risk Mitigation:", styles['Heading3']))
            story.append(Paragraph(f"Strategy: {assessment[12]}", styles['Normal']))
            story.append(Paragraph(f"Steps: {assessment[13]}", styles['Normal']))
            story.append(Paragraph(f"Timeline: {assessment[14]}", styles['Normal']))
            story.append(Spacer(1, 20))

        # Tambahkan Risk Heatmap
        story.append(Paragraph("Risk Heatmap", styles['Heading2']))
        heatmap_buffer = create_risk_heatmap(df_risk)
        heatmap_img = Image(heatmap_buffer, width=6*inch, height=4*inch)
        story.append(heatmap_img)
        story.append(Spacer(1, 12))

        # Tambahkan Risk Distribution
        story.append(Paragraph("Risk Distribution", styles['Heading2']))
        distribution_buffer = create_risk_distribution(df_risk)
        distribution_img = Image(distribution_buffer, width=6*inch, height=4*inch)
        story.append(distribution_img)
        story.append(Spacer(1, 12))

        # Tambahkan ringkasan statistik
        story.append(Paragraph("Risk Statistics", styles['Heading2']))
        risk_stats = df_risk['Risk Level'].value_counts()
        for level, count in risk_stats.items():
            story.append(Paragraph(f"{level} Risks: {count}", styles['Normal']))

        # Build PDF
        doc.build(story)
        
        # Ambil nilai PDF
        pdf = buffer.getvalue()
        buffer.close()

        # Kirim PDF sebagai response
        return send_file(
            BytesIO(pdf),
            mimetype='application/pdf',
            as_attachment=True,
            download_name='comprehensive_risk_assessment_report.pdf'
        )

    except Exception as e:
        return f"Error generating PDF: {str(e)}", 500

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/assessment')
def form():
    return render_template('assessment.html')


@app.route('/virustotal', methods=['GET', 'POST'])
def virustotal():
    if request.method == 'POST':
        url = request.form['url']
        threats = get_virustotal_threats(url)
        return render_template('virustotal.html', threats=threats, url=url)
    return render_template('virustotal.html')


@app.route('/api/threats', methods=['GET'])
def api_threats():
    indicator = request.args.get('indicator', default='', type=str)
    if indicator:
        threats = get_virustotal_threats(indicator)
        return jsonify(threats)
    return jsonify({'error': 'Indicator parameter is missing or invalid'})


@app.route('/submit', methods=['POST'])
def submit():
    try:
        # Extract form data
        assessment_name = request.form['assessmentName']
        purpose = request.form['assessmentPurpose']
        scope = request.form['scope']
        evaluation_criteria = request.form['evaluationCriteria']
        acceptance_criteria = request.form['acceptanceCriteria']
        owner = request.form['owner']
        department = request.form['department']
        other_department = request.form.get('otherDepartment', '')

        assets = request.form['assets']
        threat_sources = request.form['threatSources']
        threat_events = request.form['threatEvents']
        vulnerabilities = request.form['vulnerabilities']

        likelihood = request.form['likelihood'].strip().lower()
        impact = request.form['impact'].strip().lower()

        likelihood_value = likelihood_mapping.get(likelihood, 0)
        impact_value = impact_mapping.get(impact, 0)
        overall_risk_level = likelihood_value * impact_value

        risk_priority = request.form['riskPriority'].strip()
        mitigation_strategy = request.form['mitigationStrategy']
        mitigation_steps = request.form['mitigationSteps']
        timeline = request.form['timeline']

        # Database operations
        cursor.execute(
            """
            INSERT INTO Assessments (name, purpose, scope, evaluation_criteria, acceptance_criteria, owner, department, other_department)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (assessment_name, purpose, scope, evaluation_criteria, acceptance_criteria, owner, department,
             other_department)
        )
        assessment_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT INTO Risks (assessment_id, assets, threat_sources, threat_events, vulnerabilities)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (assessment_id, assets, threat_sources, threat_events, vulnerabilities)
        )

        cursor.execute(
            """
            INSERT INTO Risk_Analysis (assessment_id, likelihood, impact, overall_risk_level)
            VALUES (%s, %s, %s, %s)
            """,
            (assessment_id, likelihood_value, impact_value, overall_risk_level)
        )

        cursor.execute(
            """
            INSERT INTO Risk_Evaluation (assessment_id, risk_priority)
            VALUES (%s, %s)
            """,
            (assessment_id, risk_priority)
        )

        cursor.execute(
            """
            INSERT INTO Risk_Treatment (assessment_id, mitigation_strategy, mitigation_steps, timeline)
            VALUES (%s, %s, %s, %s)
            """,
            (assessment_id, mitigation_strategy, mitigation_steps, timeline)
        )

        conn.commit()
        return redirect(f'/result?assessment_id={assessment_id}')

    except Exception as e:
        conn.rollback()
        return f"Error: {str(e)}"


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
    df['Likelihood'] = pd.to_numeric(df['Likelihood'], errors='coerce').fillna(0).astype(int)
    df['Impact'] = pd.to_numeric(df['Impact'], errors='coerce').fillna(0).astype(int)
    df['Risk Level'] = df['Impact'] * df['Likelihood']

    # Enhanced visualizations
    heatmap_fig = px.scatter(
        df,
        x='Impact',
        y='Likelihood',
        color='Risk Level',
        title="Risk Heatmap",
        template="plotly_white"
    )
    heatmap_fig.update_layout(
        plot_bgcolor='white',
        paper_bgcolor='white',
        font={'size': 14}
    )

    category_pie = px.pie(
        df,
        names='Risk Level',
        title="Distribution of Risks by Risk Level",
        template="plotly_white"
    )
    category_pie.update_layout(
        showlegend=True,
        font={'size': 14}
    )

    return render_template('result.html',
                           heatmap_fig=heatmap_fig.to_html(),
                           category_pie=category_pie.to_html())


@app.route('/dashboard')
def dashboard():
    cursor.execute("SELECT COUNT(*) FROM Assessments")
    total_projects = cursor.fetchone()[0]

    cursor.execute("""
        SELECT id, name, owner, department, created_at 
        FROM Assessments
    """)
    projects = cursor.fetchall()

    if not projects:
        return render_template('dashboard.html', total_projects=total_projects, no_assessments=True)

    cursor.execute("""
        SELECT r.assessment_id, a.name, ra.likelihood, ra.impact
        FROM Risk_Analysis ra
        JOIN Assessments a ON ra.assessment_id = a.id
        JOIN Risks r ON ra.assessment_id = r.assessment_id
    """)
    data = cursor.fetchall()

    df = pd.DataFrame(data, columns=["Assessment ID", "Project Name", "Likelihood", "Impact"])

    if df.empty:
        return render_template('dashboard.html',
                               total_projects=total_projects,
                               projects=projects,
                               no_assessments=True)

    df['Likelihood'] = df['Likelihood'].astype(int)
    df['Impact'] = df['Impact'].astype(int)
    df['Risk Level'] = df['Impact'] * df['Likelihood']

    dark_template = dict(
        layout=dict(
            paper_bgcolor='#1a1a1a',
            plot_bgcolor='#1a1a1a',
            font=dict(color='#8fd6a3'),
            title=dict(font=dict(color='#8fd6a3')),
            xaxis=dict(
                gridcolor='#2d2d2d',
                zerolinecolor='#2d2d2d',
                tickfont=dict(color='#8fd6a3')
            ),
            yaxis=dict(
                gridcolor='#2d2d2d',
                zerolinecolor='#2d2d2d',
                tickfont=dict(color='#8fd6a3')
            )
        )
    )

    # Create heatmap with dark theme
    heatmap_fig = px.scatter(
        df,
        x='Impact',
        y='Likelihood',
        color='Risk Level',
        hover_data=['Assessment ID', 'Project Name'],
        title="Risk Heatmap",
    )
    heatmap_fig.update_layout(
        dark_template['layout'],
        coloraxis_colorbar=dict(
            tickfont=dict(color='#8fd6a3'),
            title=dict(font=dict(color='#8fd6a3'))
        )
    )

    # Create pie chart with dark theme
    pie_fig = px.pie(
        df,
        names='Risk Level',
        title="Risk Distribution",
        hover_data=['Project Name'],
        custom_data=['Project Name']
    )
    pie_fig.update_layout(
        dark_template['layout'],
        legend=dict(
            font=dict(color='#8fd6a3'),
            bgcolor='#1a1a1a',
            bordercolor='#2d2d2d'
        )
    )

    return render_template(
        'dashboard.html',
        total_projects=total_projects,
        projects=projects,
        heatmap_data=pio.to_json(heatmap_fig),
        pie_data=pio.to_json(pie_fig),
        no_assessments=False
    )


if __name__ == '__main__':
    app.run(debug=True)
