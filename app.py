from flask import Flask, render_template
from routes.scanner import scanner_bp

app = Flask(__name__)
app.register_blueprint(scanner_bp)

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(debug=True)