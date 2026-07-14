from flask import Flask, render_template
from scanner.engine import ScannerEngine

app = Flask(__name__)

engine = ScannerEngine()
print(engine.get_version())

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(debug=True)