import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
import pickle

# Load the dataset
data = pd.read_csv("phishing.csv")

# Preprocessing: Split the data into features (X) and target variable (y)
X = data.drop(columns=["class"])
y = data["class"]

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize the Gradient Boosting Classifier
gbc = GradientBoostingClassifier()

# Train the model
gbc.fit(X_train, y_train)

# Evaluate the model
accuracy = gbc.score(X_test, y_test)
print("Accuracy:", accuracy)

# Save the trained model using pickle
with open("model.pkl", "wb") as file:
    pickle.dump(gbc, file)

print("Model saved successfully.")
