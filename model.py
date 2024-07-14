import pandas as pd
from sklearn.model_selection import train_test_split, KFold, cross_val_score, RandomizedSearchCV
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_squared_error
import numpy as np
import warnings
import matplotlib.pyplot as plt

warnings.filterwarnings("ignore")

# Load data
df = pd.read_csv('train.csv')

df.columns = ['Date', 'Aluminium', 'Chromium', 'Cobalt', 'Copper', 'Lead', 'Manganese']

# Define densities
densities = {
    'Aluminium': 2700,
    'Chromium': 7190,
    'Cobalt': 8860,
    'Copper': 8850,
    'Lead': 11400,
    'Manganese': 7430
}

# Convert Date to datetime
df['Date'] = pd.to_datetime(df['Date'], format='%m/%d/%Y')
df.set_index('Date', inplace=True)

# Calculate volume analysis ratio
for metal, density in densities.items():
    df[metal] = df[metal] / density

# Create time-based features
df['Year'] = df.index.year
df['Month'] = df.index.month

# Select features and target for one metal (e.g., Aluminium)
X = df[['Year', 'Month']]
y = df['Aluminium']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Define the parameter grid for hyperparameter tuning with more regularization
param_grid = {
    'n_estimators': [100, 200, 300, 400, 500],
    'max_features': ['auto', 'sqrt', 'log2'],
    'max_depth': [10, 20, 30, 40],
    'min_samples_split': [5, 10, 15],
    'min_samples_leaf': [2, 4, 6],
    'bootstrap': [True, False]
}

# Initialize the model
rf = RandomForestRegressor(random_state=42)

# Perform Randomized Search with Cross-Validation
random_search = RandomizedSearchCV(estimator=rf, param_distributions=param_grid, 
                                   n_iter=100, cv=5, verbose=2, random_state=42, n_jobs=-1)

# Fit the random search model
random_search.fit(X_train, y_train)

# Best parameters from the random search
best_params = random_search.best_params_
print(f"Best Parameters: {best_params}")

# Train the model with the best parameters
best_rf = RandomForestRegressor(**best_params, random_state=42)
best_rf.fit(X_train, y_train)

# Predict on test set
y_pred_test = best_rf.predict(X_test)

# Evaluate the model on the test set
mse_test = mean_squared_error(y_test, y_pred_test)
rmse_test = np.sqrt(mse_test)
print(f"Test Set RMSE: {rmse_test}")

# Evaluate the model on the training set
y_pred_train = best_rf.predict(X_train)
mse_train = mean_squared_error(y_train, y_pred_train)
rmse_train = np.sqrt(mse_train)
print(f"Training Set RMSE: {rmse_train}")

# Cross-validation with k=20
kf = KFold(n_splits=20, shuffle=True, random_state=42)
cv_scores = cross_val_score(best_rf, X, y, cv=kf, scoring='neg_mean_squared_error')
cv_rmse_scores = np.sqrt(-cv_scores)
print(f"20-Fold Cross-Validated RMSE: {cv_rmse_scores.mean()}")

# Visualize actual vs predicted
plt.figure(figsize=(12, 6))
plt.plot(df.index, df['Aluminium'], label='Actual')
plt.plot(X_test.index, y_pred_test, label='Predicted', color='red')
plt.xlabel('Date')
plt.ylabel('Volume Analysis Ratio (Aluminium)')
plt.title('Actual vs Predicted - Aluminium')
plt.legend()
plt.grid(True)
plt.show()