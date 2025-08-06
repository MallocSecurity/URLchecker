from flask import Flask, request, render_template
from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin
from controller import Controller
import onetimescript
from db import db
from flask import jsonify
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///domains.db'
db.init_app(app)
with app.app_context():
    db.create_all() 

controller = Controller()


@app.route('/',  methods=['GET','POST'])
def home():
    
    try:
        url = request.form['url']
        result = controller.main(url)
        output = result
    except:
        output = 'NA'

    return render_template('index.html', output=output)


@app.route('/api/check-domain', methods=['POST'])
def check_domain_api():
    try:
        data = request.get_json()
        url = data.get('url')

        if not url:
            return jsonify({'error': 'Missing URL'}), 400

        result = controller.main(url)

        # Expected result is a dict with trust_score, reason, etc.
        return jsonify({
            'status': result.get('status'),
            'trust_score': result.get('trust_score'),
            'reason': result.get('reason', 'No specific reason provided.'),
            'url': result.get('url'),
            'age': result.get('age'),
            'rank': result.get('rank'),
            'response_status': result.get('response_status'),
            'is_url_shortened': result.get('is_url_shortened'),
            'hsts_support': result.get('hsts_support'),
            'ssl': result.get('ssl'),
            'whois': result.get('whois'),
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/update-db')
def update_db(): 
    try:
        with app.app_context():
            response = onetimescript.update_db()
            print("Database populated successfully!")
            return response, 200
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return "An error occurred: " + str(e), 500

@app.route('/update-json')
def update_json(): 
    try:
        with app.app_context():
            response = onetimescript.update_json()
            print("JSON updated successfully!")
            return response, 200
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return "An error occurred: " + str(e), 500


if __name__ == '__main__':
    app.debug = True
    app.run()