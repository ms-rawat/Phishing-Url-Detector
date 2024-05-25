import pickle
import numpy as np

def predict_phishing(features):
    # Reshape the input features to ensure it has the correct shape
    features = np.array(features).reshape(1, -1)

    # Load the trained model
    with open("model.pkl", "rb") as file:
        model = pickle.load(file)
    
    # Make predictions using the loaded model
    prediction = model.predict(features)
    probability = model.predict_proba(features)
    
    # Return the prediction and probability
    return prediction, probability