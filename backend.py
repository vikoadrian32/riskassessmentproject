from flask import Flask, render_template, request, redirect, url_for, jsonify
import mysql.connector
import requests
import base64
from dash import Dash, dcc, html
import plotly.express as px
import pandas as pd
import plotly.io as pio
import os
from dotenv import load_dotenv

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

    # Enhanced visualizations
    heatmap_fig = px.scatter(
        df,
        x='Impact',
        y='Likelihood',
        color='Risk Level',
        hover_data=['Assessment ID', 'Project Name'],
        title="Risk Heatmap",
        template="plotly_white"
    )
    heatmap_fig.update_layout(
        plot_bgcolor='white',
        paper_bgcolor='white',
        font={'size': 14}
    )

    pie_fig = px.pie(
        df,
        names='Risk Level',
        title="Risk Distribution",
        hover_data=['Assessment ID', 'Project Name'],
        template="plotly_white"
    )
    pie_fig.update_layout(
        showlegend=True,
        font={'size': 14}
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
