import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns


def load_and_preprocess_data(filepath):
    df = pd.read_csv(filepath)
    df.dropna(inplace=True)

    # Encode the 'Label' column
    label_encoder = LabelEncoder()
    df['Label'] = label_encoder.fit_transform(df['Label'])

    # Select only numeric features, drop the label column
    X = df.select_dtypes(include=["float64", "int64"]).drop(columns=['Label'])
    y = df['Label']
    
    return X, y, label_encoder


def train_and_evaluate(X, y, label_encoder):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

    # Confusion matrix
    conf_matrix = confusion_matrix(y_test, y_pred)
    sns.heatmap(conf_matrix, annot=True, fmt='d',
                xticklabels=label_encoder.classes_,
                yticklabels=label_encoder.classes_)
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.show()


def main():
    filepath = "VPNNonVPN.csv"  # Replace with your actual path
    print(f"Loading dataset from: {filepath}")
    
    X, y, label_encoder = load_and_preprocess_data(filepath)
    train_and_evaluate(X, y, label_encoder)


if __name__ == "__main__":
    main()
