from scipy.io import arff
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns

def load_arff_to_dataframe(filepath):
    data, meta = arff.loadarff(filepath)
    df = pd.DataFrame(data)
    
    # Decode byte strings to regular strings
    for col in df.select_dtypes([object]):
        df[col] = df[col].str.decode("utf-8")
    
    return df

def preprocess_data(df, label_column='class'):
    # Encode labels
    le = LabelEncoder()
    df[label_column] = le.fit_transform(df[label_column])
    
    # Drop missing values (if any)
    df.dropna(inplace=True)
    
    X = df.drop(columns=[label_column])
    y = df[label_column]
    
    return X, y, le

def train_and_evaluate(X, y, label_encoder):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    
    print("=== Classification Report ===")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

    conf_matrix = confusion_matrix(y_test, y_pred)
    sns.heatmap(conf_matrix, annot=True, fmt='d',
                xticklabels=label_encoder.classes_,
                yticklabels=label_encoder.classes_,
                cmap="Blues")
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.show()

def main():
    filepath = "TimeBasedFeatures-Dataset-120s-VPN.arff"  # Replace with your path
    df = load_arff_to_dataframe(filepath)
    
    print(f"Loaded data with {df.shape[0]} rows and {df.shape[1]} columns")
    print("Available columns:", df.columns.tolist())

    X, y, label_encoder = preprocess_data(df, label_column='class')  # Adjust if label column is named differently
    train_and_evaluate(X, y, label_encoder)

if __name__ == "__main__":
    main()