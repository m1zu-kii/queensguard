import math
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import xgboost as xgb

from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"), override=False)

from kagglehub import KaggleDatasetAdapter
import kagglehub
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import accuracy_score
from sklearn.linear_model import SGDClassifier
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn import config_context


DATASET_HANDLE = "devendra416/ddos-datasets"
FILE_PATH = "ddos_balanced/final_dataset.csv"
DATASET_ROW_COUNT = 12_794_627
ROWS_TO_LOAD = DATASET_ROW_COUNT // 5
KNN_SAMPLE_ROWS = 100_000
VOTING_TRAIN_ROWS = 100_000
CALIBRATION_ROWS = 20_000
TEST_ROWS = 10_000
N_NEIGHBORS = 5
RANDOM_STATE = 42
EXCLUDED_COLUMNS = ("Unnamed: 0", "Flow ID", "Src IP", "Dst IP", "Timestamp")

def prepare_dataset(data: pd.DataFrame) -> pd.DataFrame:
    """Drop identifier columns and return finite numeric features with labels."""
    data = data.drop(columns=list(EXCLUDED_COLUMNS), errors="ignore").copy()
    if "Label" not in data.columns:
        raise ValueError("The dataset must contain a 'Label' column.")

    labels = data.pop("Label")
    raw_features = data
    features = pd.DataFrame(index=raw_features.index)
    for column_name in raw_features.columns:
        column = raw_features[column_name]
        numeric_column = pd.to_numeric(column, errors="coerce")
        has_string_values = (column.notna() & numeric_column.isna()).any()
        if has_string_values:
            category_codes, _ = pd.factorize(
                column.astype("string"), sort=True
            )
            features[column_name] = category_codes.astype(np.float32)
        else:
            features[column_name] = numeric_column

    features = features.replace([np.inf, -np.inf], np.nan)
    valid_rows = raw_features.notna().all(axis=1) & features.notna().all(axis=1)
    label_values = labels.astype("string").str.strip().str.casefold()
    encoded_labels = label_values.map(
        {"benign": 0, "ddos": 1, "0": 0, "1": 1}
    )
    unknown_labels = labels.notna() & encoded_labels.isna()
    if unknown_labels.any():
        unexpected = labels.loc[unknown_labels].unique().tolist()
        raise ValueError(f"Unsupported label values: {unexpected}")
    valid_rows &= encoded_labels.notna()

    features = features.loc[valid_rows].astype(np.float32)
    features["Label"] = encoded_labels.loc[valid_rows].astype(np.int8)
    return features

# Load a repeatable, evenly spaced sample across the complete source file.
def load_ddos_dataset(row_limit: int = ROWS_TO_LOAD) -> pd.DataFrame:
    """Load a repeatable, evenly spaced sample across the complete source file."""
    if row_limit <= 0:
        raise ValueError("row_limit must be greater than zero.")

    raw_row_limit = min(DATASET_ROW_COUNT, math.ceil(row_limit * 1.01))
    pandas_kwargs: dict[str, Any] = {"nrows": raw_row_limit}
    if raw_row_limit < DATASET_ROW_COUNT:
        sample_count = min(DATASET_ROW_COUNT, raw_row_limit + 1)
        spacing = DATASET_ROW_COUNT / sample_count
        offset = np.random.default_rng(RANDOM_STATE).uniform(0, spacing)

        def skip_unselected_rows(line_number: int) -> bool:
            if line_number == 0:
                return False
            row_number = line_number - 1
            return math.floor((row_number + offset) / spacing) == math.floor(
                (row_number - 1 + offset) / spacing
            )

        pandas_kwargs["skiprows"] = skip_unselected_rows

    data = kagglehub.dataset_load(
        KaggleDatasetAdapter.PANDAS,
        DATASET_HANDLE,
        FILE_PATH,
        pandas_kwargs=pandas_kwargs,
    )
    return prepare_dataset(data).head(row_limit)

# Split the dataset into training and testing sets with stratification.
def _split_dataset(
    data: pd.DataFrame, test_rows: int = TEST_ROWS
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    if test_rows <= 0:
        raise ValueError("test_rows must be greater than zero.")
    if "Label" not in data.columns or len(data) < 2:
        raise ValueError("At least two labeled rows are required.")

    feature_columns = data.drop(columns="Label")
    if feature_columns.shape[1] == 0:
        raise ValueError("The dataset must contain at least one feature.")

    features = feature_columns.to_numpy(dtype=np.float32, copy=False)
    labels = data["Label"].to_numpy(copy=False)
    if np.unique(labels).size < 2:
        raise ValueError("At least two label classes are required for evaluation.")
    actual_test_rows = min(test_rows, max(1, len(data) // 5))
    if actual_test_rows >= len(data):
        raise ValueError("The dataset must contain rows for both training and testing.")

    return train_test_split(
        features,
        labels,
        test_size=actual_test_rows,
        random_state=RANDOM_STATE,
        stratify=labels,
    )

# Fit and evaluate exact KNN on a reproducible, stratified holdout.
def knn_processing(
    data: pd.DataFrame, sample_rows: int = KNN_SAMPLE_ROWS
) -> tuple[Pipeline, float]:
    """Evaluate exact KNN on a reproducible, stratified holdout."""
    if sample_rows <= 0:
        raise ValueError("sample_rows must be greater than zero.")
    sample = data.sample(n=min(sample_rows, len(data)), random_state=RANDOM_STATE)
    X_train, X_test, y_train, y_test = _split_dataset(sample)
    model = Pipeline(
        [
            ("scale", StandardScaler(copy=False)),
            (
                "model",
                KNeighborsClassifier(
                    n_neighbors=N_NEIGHBORS,
                    algorithm="brute",
                    n_jobs=1,
                ),
            ),
        ]
    )

    with config_context(working_memory=128):
        model.fit(X_train, y_train)
        prediction = model.predict(X_test)
    return model, float(accuracy_score(y_test, prediction))

def svm_processing(data: pd.DataFrame) -> tuple[Pipeline, float]:
    """Fit and evaluate a linear SVM trained via SGD."""
    X_train, X_test, y_train, y_test = _split_dataset(data)

    clf = make_pipeline(
        StandardScaler(copy=False),
        SGDClassifier(
            loss="hinge",
            alpha=0.01,
            max_iter=1000,
            tol=1e-3,
            random_state=RANDOM_STATE,
        ),
    )

    clf.fit(X_train, y_train)
    prediction = clf.predict(X_test)
    return clf, float(accuracy_score(y_test, prediction))

def xgb_processing(data: pd.DataFrame) -> tuple[Any, float]:
    """Fit and evaluate an XGBoost classifier."""

    X_train, X_test, y_train, y_test = _split_dataset(data)

    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=RANDOM_STATE,
        eval_metric="logloss",
    )

    model.fit(X_train, y_train)
    prediction = model.predict(X_test)
    return model, float(accuracy_score(y_test, prediction))


def train_voting_models(data: pd.DataFrame) -> dict[str, Any]:
    """Train calibrated classifiers for live unanimous voting."""
    if "Label" not in data.columns:
        raise ValueError("Training data must contain a 'Label' column.")

    sample_size = min(len(data), VOTING_TRAIN_ROWS + CALIBRATION_ROWS)
    sample = data.sample(n=sample_size, random_state=RANDOM_STATE)
    feature_columns = sample.drop(columns="Label")
    if feature_columns.shape[1] == 0:
        raise ValueError("Training data must contain at least one feature.")

    X = feature_columns.to_numpy(dtype=np.float32, copy=False)
    y = sample["Label"].to_numpy(copy=False)
    if np.unique(y).size != 2:
        raise ValueError("Voting models require both Benign and DDoS training rows.")

    calibration_size = min(CALIBRATION_ROWS, max(1, len(sample) // 5))
    X_train, X_calibration, y_train, y_calibration = train_test_split(
        X,
        y,
        test_size=calibration_size,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    estimators: dict[str, Any] = {
        "knn": Pipeline(
            [
                ("scale", StandardScaler(copy=False)),
                (
                    "model",
                    KNeighborsClassifier(
                        n_neighbors=N_NEIGHBORS,
                        algorithm="brute",
                        n_jobs=1,
                    ),
                ),
            ]
        ),
        "svm": make_pipeline(
            StandardScaler(copy=False),
            SGDClassifier(
                loss="hinge",
                alpha=0.01,
                max_iter=1000,
                tol=1e-3,
                random_state=RANDOM_STATE,
            ),
        ),
        "xgb": xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=RANDOM_STATE,
            eval_metric="logloss",
            tree_method="hist",
            n_jobs=4,
        ),
    }

    calibrated_models: dict[str, Any] = {}
    for name, estimator in estimators.items():
        estimator.fit(X_train, y_train)
        calibrated = CalibratedClassifierCV(
            estimator=FrozenEstimator(estimator),
            method="sigmoid",
        )
        calibrated.fit(X_calibration, y_calibration)
        calibrated_models[name] = calibrated

    return calibrated_models


def run_models(data: pd.DataFrame) -> dict[str, tuple[Any, float]]:
    """Run the bounded KNN check, linear SVM, and XGBoost."""
    results: dict[str, tuple[Any, float]] = {}

    knn_model, knn_accuracy = knn_processing(data)
    results["knn"] = (knn_model, knn_accuracy)
    print(f"KNN accuracy ({min(KNN_SAMPLE_ROWS, len(data)):,} rows): {knn_accuracy:.2%}")

    svm_model, svm_accuracy = svm_processing(data)
    results["svm"] = (svm_model, svm_accuracy)
    print(f"Linear SVM accuracy (all rows): {svm_accuracy:.2%}")

    xgb_model, xgb_accuracy = xgb_processing(data)
    results["xgb"] = (xgb_model, xgb_accuracy)
    print(f"XGBoost accuracy (all rows): {xgb_accuracy:.2%}")

    return results

def main() -> None:
    data = load_ddos_dataset()
    print(f"Loaded {len(data):,} cleaned rows.")
    run_models(data)

if __name__ == "__main__":
    main()