from flask import Flask, render_template, jsonify

# Initialize Flask app
app = Flask(__name__)

# Route for the main report page
@app.route("/")
def home():
    return render_template("report.html")

# API endpoint to fetch report data
@app.route("/api/report-data")
def report_data():
    # Example data (replace with real scan results)
    return jsonify({
        "vulnerabilities": [12, 8, 5, 3],  # XSS, SQLi, CSRF, JWT Issues
        "attack_paths": [
            {"source": "Web Server", "target": "Database"},
            {"source": "Web Server", "target": "File Server"}
        ],
        "data_leaks": ["user@example.com", "192.168.1.1"],
        "recommendations": [
            {
                "title": "XSS Protection",
                "content": "Add Content Security Policy headers and sanitize user inputs"
            },
            {
                "title": "SQLi Mitigation",
                "content": "Implement prepared statements using SQLAlchemy"
            }
        ]
    })

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)