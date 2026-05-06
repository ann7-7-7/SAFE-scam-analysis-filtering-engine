"""
Supervised NLP baseline experiment for S.A.F.E.

This script trains a Logistic Regression classifier on TF-IDF features using
synthetic labeled messages (scam vs safe). It is for evaluation/report evidence
only and is separate from the production rule-based checker.

Important:
- This does NOT replace the live website checker.
- The live S.A.F.E web demo continues to use the existing rule-based,
  explainable checker layer for stable demonstrations.
- Do not load these pickles into the Flask app unless you add a dedicated,
  isolated evaluation route; the website is unchanged by this experiment.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split


def _label_counts(series: pd.Series) -> str:
    counts = series.value_counts().sort_index()
    parts = [f"{label}: {int(counts[label])}" for label in sorted(counts.index)]
    return ", ".join(parts)


def main() -> None:
    root = Path(__file__).resolve().parent
    data_path = root / "data" / "safe_dataset.csv"
    models_dir = root / "models"
    results_path = root / "model_results.txt"
    cm_image_path = root / "model_confusion_matrix.png"

    models_dir.mkdir(parents=True, exist_ok=True)

    if not data_path.exists():
        raise FileNotFoundError(f"Dataset not found: {data_path}")

    df = pd.read_csv(data_path)
    required_cols = {"message", "label"}
    if not required_cols.issubset(df.columns):
        raise ValueError(f"Dataset must contain columns: {required_cols}")

    X = df["message"].astype(str)
    y = df["label"].astype(str)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    train_class_str = _label_counts(y_train)
    test_class_str = _label_counts(y_test)

    vectorizer = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=1,
        max_df=0.95,
    )

    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)

    model = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
    model.fit(X_train_tfidf, y_train)

    y_pred = model.predict(X_test_tfidf)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, pos_label="scam", zero_division=0)
    recall = recall_score(y_test, y_pred, pos_label="scam", zero_division=0)
    f1 = f1_score(y_test, y_pred, pos_label="scam", zero_division=0)
    report = classification_report(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=["safe", "scam"])

    pred_classes = np.unique(y_pred)
    single_class_warning = ""
    if len(pred_classes) < 2:
        single_class_warning = (
            "\nWARNING: The model predicted only one class on the test set. "
            "Metrics may be misleading; review data balance and features.\n"
        )

    lines = [
        "S.A.F.E Supervised NLP Baseline (Logistic Regression + TF-IDF)",
        "This baseline is separate from the live rule-based web checker.",
        "",
        f"Dataset path: {data_path}",
        f"Total samples: {len(df)}",
        f"Full dataset class distribution: {_label_counts(y)}",
        "",
        f"Train samples: {len(X_train)} ({train_class_str})",
        f"Test samples:  {len(X_test)} ({test_class_str})",
        "",
        "Hyperparameters: LogisticRegression(max_iter=1000, class_weight='balanced')",
        "Split: stratified train_test_split(test_size=0.2, random_state=42)",
        "",
        f"Accuracy:  {accuracy:.4f}",
        f"Precision (scam): {precision:.4f}",
        f"Recall (scam):    {recall:.4f}",
        f"F1-score (scam):  {f1:.4f}",
        "",
        "Classification report:",
        report.rstrip(),
        "",
        "Confusion matrix (rows=true, cols=pred; order=[safe, scam]):",
        str(cm),
        single_class_warning,
    ]

    output_text = "\n".join(line for line in lines if line is not None)
    print(output_text)
    results_path.write_text(output_text, encoding="utf-8")

    joblib.dump(model, models_dir / "logistic_regression_model.pkl")
    joblib.dump(vectorizer, models_dir / "tfidf_vectorizer.pkl")

    try:
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(5, 4))
        im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
        ax.figure.colorbar(im, ax=ax)
        ax.set(
            xticks=np.arange(2),
            yticks=np.arange(2),
            xticklabels=["safe", "scam"],
            yticklabels=["safe", "scam"],
            ylabel="True label",
            xlabel="Predicted label",
            title="Confusion Matrix",
        )
        thresh = cm.max() / 2.0 if cm.max() > 0 else 0
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(
                    j,
                    i,
                    format(cm[i, j], "d"),
                    ha="center",
                    va="center",
                    color="white" if cm[i, j] > thresh else "black",
                )
        fig.tight_layout()
        fig.savefig(cm_image_path, dpi=150)
        plt.close(fig)
        print(f"\nSaved confusion matrix image to: {cm_image_path}")
    except Exception as exc:  # Optional output only
        print(f"\nSkipping confusion matrix image (matplotlib unavailable): {exc}")

    print(f"Saved metrics to: {results_path}")
    print(f"Saved model to: {models_dir / 'logistic_regression_model.pkl'}")
    print(f"Saved vectorizer to: {models_dir / 'tfidf_vectorizer.pkl'}")


if __name__ == "__main__":
    main()
