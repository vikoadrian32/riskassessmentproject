from flask import Flask, render_template, request, redirect, url_for
import mysql.connector
from dash import Dash, dcc, html
import plotly.express as px
import pandas as pd
import plotly.io as pio

# Flask app
app = Flask(__name__)

# Koneksi ke database MySQL
conn = mysql.connector.connect(
    host="127.0.0.1",
    port="3306",
    user="root",
    password="",
    database="riskassessment"
)
cursor = conn.cursor()

# Mapping untuk Likelihood dan Impact
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

# Integrasi dengan Dash untuk Visualisasi
dash_app = Dash(__name__, server=app, url_base_pathname='/dashboard/')
dash_app.layout = html.Div([
    html.H1('Risk Assessment Dashboard'),
    dcc.Graph(id='heatmap'),
    dcc.Graph(id='category-pie')
])

# Route untuk halaman Home
@app.route('/')
def home():
    return render_template('home.html')

# Route untuk form utama
@app.route('/assessment')
def form():
    return render_template('assessment.html')

# Route untuk menerima data dari form
@app.route('/submit', methods=['POST'])
def submit():
    # Ambil data dari form
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

    # Hitung Overall Risk Level (Likelihood x Impact)
    likelihood_value = likelihood_mapping.get(likelihood, 0)
    impact_value = impact_mapping.get(impact, 0)
    overall_risk_level = likelihood_value * impact_value

    risk_priority = request.form['riskPriority'].strip()
    mitigation_strategy = request.form['mitigationStrategy']
    mitigation_steps = request.form['mitigationSteps']
    timeline = request.form['timeline']

    try:
        cursor.execute(
            """
            INSERT INTO Assessments (name, purpose, scope, evaluation_criteria, acceptance_criteria, owner, department, other_department)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (assessment_name, purpose, scope, evaluation_criteria, acceptance_criteria, owner, department, other_department)
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

# Route untuk melihat hasil per project
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

    # Sekarang, hitung Risk Level berdasarkan nilai numerik
    df['Risk Level'] = df['Impact'] * df['Likelihood']
    heatmap_fig = px.scatter(
        df, x='Impact', y='Likelihood', color='Risk Level',
        title="Risk Heatmap"
    )

    category_pie = px.pie(df, names='Risk Level', title="Distribution of Risks by Risk Level")
    return render_template('result.html', heatmap_fig=heatmap_fig.to_html(), category_pie=category_pie.to_html())

# Route untuk dashboard
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
        return render_template('dashboard.html', total_projects=total_projects, projects=projects, no_assessments=True)

    # 🔧 Konversi ke integer sebelum perkalian
    df['Likelihood'] = df['Likelihood'].astype(int)
    df['Impact'] = df['Impact'].astype(int)
    df['Risk Level'] = df['Impact'] * df['Likelihood']

    # 🔥 Membuat heatmap
    heatmap_fig = px.scatter(
        df, x='Impact', y='Likelihood', color='Risk Level',
        hover_data=['Assessment ID', 'Project Name'],
        title="Risk Heatmap"
    )

    # 🔥 Membuat pie chart
    pie_fig = px.pie(df, names='Risk Level', title="Risk Distribution", hover_data=['Assessment ID', 'Project Name'])

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
