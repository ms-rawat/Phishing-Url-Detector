from flask import Flask, request, jsonify
from feature import FeatureExtraction
from model import predict_phishing
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get('url')
    print(url)

    # Initialize FeatureExtraction instance with the input URL
    obj = FeatureExtraction(url)

    # Extract features
    features = obj.features

    # Pass features to the prediction function
    prediction, probability = predict_phishing(features)

    return jsonify({'probability': probability.tolist(), 'prediction': prediction.tolist()})

if __name__ == "__main__":
    app.run(debug=True)
