from flask import Flask
from analytical_questions import analytical_questions_bp
from nist_cve_flask.api_development import api_development_bp

app = Flask(__name__)
app.register_blueprint(analytical_questions_bp)
app.register_blueprint(api_development_bp)

if __name__ == '__main__':
    app.run(debug=True)