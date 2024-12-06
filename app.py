from flask import Flask, request, jsonify
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder
from extract_features import process_urls

# Initialize Flask app
app = Flask(__name__)

# Load the trained model
model_path = 'models/rf_model_phiusiil_v3.1.pkl'
best_rf_model = joblib.load(model_path)

# Load training feature template for alignment
# required_features = ['URLLength', 'DomainLength', 'IsDomainIP', 'TLD', 'TLDLength', 'NoOfSubDomain', 'IsHTTPS', 'NoOfLettersInURL', 'NoOfDegitsInURL', 'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL', 'LetterRatioInURL', 'DegitRatioInURL', 'SpacialCharRatioInURL', 'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio', 'URLSimilarityIndex', 'CharContinuationRate']
required_features = ["URLLength", "DomainLength", "IsDomainIP", "TLD", "TLDLength", "NoOfSubDomain", "IsHTTPS", "NoOfLettersInURL", "NoOfDegitsInURL", "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL", "LetterRatioInURL", "DegitRatioInURL", "SpacialCharRatioInURL", "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio", "URLSimilarityIndex", "CharContinuationRate", "URLCharProb", "TLDLegitimateProb"]
# Create a function to prepare features for prediction
def prepare_features(input_features, required_features):
    full_features = {feature: input_features.get(feature, 0) for feature in required_features}
    return pd.DataFrame([full_features])

# Encode categorical features
label_encoder = LabelEncoder()

@app.route('/predict', methods=['GET'])
def predict_url():
    urls = []
    # try:
    # Obtain 'url' query parameter
    url = request.args.get('url', None)
    if not url:
        return jsonify({"error": "Missing 'url' query parameter"}), 400
    
    urls.append(url)
    features_list = process_urls(urls)

    
    # Align features with the trained model's feature set
    prepared_features = prepare_features(features_list[0], required_features)

    for col in ['TLD']:
        prepared_features[col] = label_encoder.fit_transform(prepared_features[col])

    # print(type(prepared_features))
    # print(prepared_features)
    # prepared_features.drop(columns=["URLSimilarityIndex", "NoOfExternalRef", "LineOfCode", "NoOfImage", "NoOfJS", "Domain"])
    # Predict the classification
    prediction = best_rf_model.predict(prepared_features)
    result = "Legitimate" if prediction[0] == 1 else "Phishing"

    return jsonify({"url": url, "prediction": result})
    # except Exception as e:
    #     return jsonify({"error": "An error occurred during prediction", "details": str(e)}), 500

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True, port=8800)