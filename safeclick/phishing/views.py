from django.shortcuts import render
from django.http import JsonResponse
import pickle
from .feature_extraction import extract_features
import pandas as pd
import logging
from .custom_models import GradientBoostingClassifierFromScratch, RandomForestClassifierFromScratch, DecisionTreeClassifierFromScratch

# Configure logging
logging.basicConfig(level=logging.DEBUG)  # Use DEBUG for verbose logging
logger = logging.getLogger(__name__)

# Load the trained model

import joblib
model = joblib.load('custom_gradient_booting_model_5.pkl')
logger.debug("model loaded: ", model)

# Home view
def home(request):
    logger.debug("In Home  URL") 
    prediction_text = None
    if request.method == 'POST':
        url = request.POST.get('url')  # Get the user-input URL
        result = predict_url_safety(url)  # Use the helper function
        if 'error' in result:
            prediction_text = result['error']
        else:
            prediction_text = "Safe" if result['is_safe'] else "Unsafe"

    return render(request, 'phishing/index.html', {'prediction': prediction_text})

# API endpoint for URL classification
def classify_url(request):
    logger.debug("In classify request URL") 
    url = request.GET.get('url')  # Get URL from query parameters
    if not url:
        return JsonResponse({'error': "URL is required"}, status=400)

    result = predict_url_safety(url)  # Use the helper function
    if 'error' in result:
        return JsonResponse({'error': result['error']}, status=500)

    is_safe = bool(result['is_safe']) if result['is_safe'] is not None else None

    return JsonResponse({'is_safe': is_safe})


def predict_url_safety(url):
    logger.debug("In predict URL")  # Log the features
    if not url:
        logger.debug("In predict URL if condition error")
        return {'error': "URL is required", 'is_safe': None}

    if model is None:
        logger.debug("In predict URL if condition model none")
        return {'error': "Model is not loaded. Please check the server setup.", 'is_safe': None}

    try:
        # Extract features and make predictions
        extracted_features = extract_features(url)
        logger.debug(f"Extracted Features: {extracted_features}")  # Log the features

        expected_features = ['NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
       'NumDashInHostname', 'NumUnderscore', 'NumPercent',
       'NumQueryComponents', 'NumAmpersand', 'NumNumericChars', 'NoHttps',
       'RandomString', 'IpAddress', 'DomainInPaths', 'HostnameLength',
       'PathLength', 'QueryLength', 'NumSensitiveWords', 'EmbeddedBrandName',
       'PctExtHyperlinks', 'PctExtResourceUrls', 'ExtFavicon', 'InsecureForms',
       'RelativeFormAction', 'ExtFormAction', 'PctNullSelfRedirectHyperlinks',
       'FrequentDomainNameMismatch', 'SubmitInfoToEmail', 'IframeOrFrame',
       'MissingTitle', 'SubdomainLevelRT', 'UrlLengthRT',
       'PctExtResourceUrlsRT', 'AbnormalExtFormActionR', 'ExtMetaScriptLinkRT',
       'PctExtNullSelfRedirectHyperlinksRT']
        # Align extracted features with expected feature names
        for feature in expected_features:
            if feature not in extracted_features:
                extracted_features[feature] = 0  # Default value for missing features

        aligned_features = {key: extracted_features[key] for key in expected_features}
        aligned_features_df = pd.DataFrame([aligned_features])
        logger.debug(f"DataFrame for Prediction: {aligned_features_df}")  # Log the DataFrame
        prediction = model.predict(aligned_features_df)[0]
        is_safe = prediction == 1  # If 1, the URL is safe; if 0, it's unsafe
        return {'is_safe': is_safe}
    except Exception as e:
        print(f"Error during classification: {str(e)}")
        return {'error': "Unable to classify the URL. Please try again later.", 'is_safe': None}
