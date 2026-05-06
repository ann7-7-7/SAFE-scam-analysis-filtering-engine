# S.A.F.E Supervised NLP Baseline Evidence

This folder contains evidence for the supervised NLP baseline experiment developed for S.A.F.E. The baseline uses TF-IDF feature extraction with Logistic Regression to classify messages as scam or safe. It is separate from the live rule-based web checker.

## 1. Files included

- **safe_dataset.csv** — Synthetic labelled scam/safe dataset used for training and testing.
- **train_model.py** — Python script used to train and evaluate the Logistic Regression model.
- **model_results.txt** — Saved evaluation results including accuracy, precision, recall, F1-score and confusion matrix.

## 2. Dataset summary

- Total samples: 140
- Safe samples: 60
- Scam samples: 80
- Train samples: 112
- Test samples: 28
- Split: stratified `train_test_split(test_size=0.2, random_state=42)`

## 3. Model summary

- Feature extraction: TF-IDF
- Classifier: Logistic Regression
- Hyperparameters: `max_iter=1000`, `class_weight='balanced'`

## 4. Evaluation summary

- Accuracy: 89.29%
- Precision for scam: 84.21%
- Recall for scam: 100%
- F1-score for scam: 91.43%
- Confusion matrix:

  ```
  [[9, 3],
   [0, 16]]
  ```

  (Rows: true labels in order safe, scam; columns: predicted labels in order safe, scam.)

## 5. Interpretation

The baseline correctly identified all scam messages in the test set, achieving 100% scam recall. It misclassified 3 safe messages as scam, showing that further tuning and a larger dataset are needed to reduce false positives before integrating the model into the live website.

## 6. Relationship to live website

The live S.A.F.E website currently uses an explainable rule-based checker for stable demonstration. This supervised NLP baseline supports the planned AI/NLP direction and is intended for future integration after further testing.
