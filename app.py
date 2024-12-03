from flask import Flask, request, jsonify
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder

# Initialize Flask app
app = Flask(__name__)

# Load the trained model
model_path = 'rf_model_phiusiil_random_search.pkl'
best_rf_model = joblib.load(model_path)

# Load training feature template for alignment
required_features = ['URLLength', 'Domain', 'DomainLength', 'IsDomainIP', 'TLD', 'URLSimilarityIndex', 'CharContinuationRate', 'TLDLegitimateProb', 'URLCharProb', 'TLDLength', 'NoOfSubDomain', 'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio', 'NoOfLettersInURL', 'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL', 'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL', 'SpacialCharRatioInURL', 'IsHTTPS', 'LineOfCode', 'LargestLineLength', 'HasTitle', 'DomainTitleMatchScore', 'URLTitleMatchScore', 'HasFavicon', 'Robots', 'IsResponsive', 'NoOfURLRedirect', 'NoOfSelfRedirect', 'HasDescription', 'NoOfPopup', 'NoOfiFrame', 'HasExternalFormSubmit', 'HasSocialNet', 'HasSubmitButton', 'HasHiddenFields', 'HasPasswordField', 'Bank', 'Pay', 'Crypto', 'HasCopyrightInfo', 'NoOfImage', 'NoOfCSS', 'NoOfJS', 'NoOfSelfRef', 'NoOfEmptyRef', 'NoOfExternalRef']

# Create a function to prepare features for prediction
def prepare_features(input_features, required_features):
    full_features = {feature: input_features.get(feature, 0) for feature in required_features}
    return pd.DataFrame([full_features])

# Encode categorical features
label_encoder = LabelEncoder()

@app.route('/predict', methods=['GET'])
def predict_url():
    try:
        # Obtain 'url' query parameter
        url = request.args.get('url', None)
        if not url:
            return jsonify({"error": "Missing 'url' query parameter"}), 400

        # Mockup feature extraction for given URL (replace with actual feature extraction logic)
        extracted_features = {'Domain': 'example', 'TLD': 'com', 'URLLength': len(url)}

        # Align features with the trained model's feature set
        ordered_features = prepare_features(extracted_features, required_features)
        for col in ['Domain', 'TLD']:
            ordered_features[col] = label_encoder.fit_transform(ordered_features[col])

        # Predict the classification
        prediction = best_rf_model.predict(ordered_features)
        result = "Legitimate" if prediction[0] == 1 else "Phishing"

        return jsonify({"url": url, "prediction": result})
    except Exception as e:
        return jsonify({"error": "An error occurred during prediction", "details": str(e)}), 500

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True, port=8800)