import pickle
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split

# Generate Sample Data: (Username Length, Password Length, Failed Attempts)
X = np.array([
    [5, 8, 0],  # Normal login
    [6, 10, 1],  # Normal login
    [4, 6, 2],  # Normal login
    [3, 5, 3],  # Intrusion detected
    [7, 12, 1],  # Normal login
    [5, 7, 3],  # Intrusion detected
    [4, 6, 3],  # Intrusion detected
    [8, 10, 0],  # Normal login
    [6, 9, 2],  # Normal login
    [5, 7, 3],  # Intrusion detected
])

# Labels: 0 = Safe, 1 = Intrusion Detected
y = np.array([0, 0, 0, 1, 0, 1, 1, 0, 0, 1])

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Decision Tree Model
model = DecisionTreeClassifier()
model.fit(X_train, y_train)

# Save the trained model
with open('intrusion_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("✅ Model Trained and Saved as 'intrusion_model.pkl' 🎯")
