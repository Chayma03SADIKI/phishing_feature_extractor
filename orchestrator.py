"""
orchestrator.py — robuste, tolérant aux erreurs
Author: Chayma Sadiki (adapté)
"""

import os
import json
import pandas as pd
import traceback
from tqdm import tqdm

# --------------------------------------------------
# Global paths (use forward slashes under Windows)
# --------------------------------------------------
BENIGN_PATH = "D:/Downloads/benign"
MALICIOUS_PATH = "D:/Downloads/malicious"

# --------------------------------------------------
# Import feature extractor modules (assumed to expose functions)
# - extract_general_features(data: dict) -> dict
# - extract_hostinfo_features(host_info: dict) -> dict
# - extract_contentinfo_features(content_info: dict) -> dict
# - extract_additional_features(additional: dict) -> dict
# --------------------------------------------------
from extract_general_features import extract_general_features
from extract_hostinfo_features import extract_hostinfo_features
from extract_contentinfo_features import extract_contentinfo_features
from extract_additional_features import extract_additional_features


def safe_call(func, arg, fname, filename):
    """
    Call func(arg) safely: if it raises, return {} and print a helpful trace.
    fname = name of the extractor for logging.
    filename = current JSON filename for context.
    """
    try:
        # Ensure arg is at least a dict (some JSON files may contain null)
        if arg is None:
            arg = {}
        result = func(arg)
        if not isinstance(result, dict):
            # defensive: ensure we always return a dict
            return {}
        return result
    except Exception as e:
        print(f"Extractor error in '{fname}' while processing '{filename}': {e}")
        traceback.print_exc()
        return {}


def load_json_file(file_path, filename):
    """Robust JSON loader returning dict or None (and prints errors)."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                print(f"Empty file skipped: {filename}")
                return None
            return json.loads(content)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in '{filename}': {e}")
        return None
    except Exception as e:
        print(f"Error reading '{filename}': {e}")
        traceback.print_exc()
        return None


def build_global_dataframe() -> pd.DataFrame:
    data_rows = []

    categories = [
        (BENIGN_PATH, 1, "benign"),
        (MALICIOUS_PATH, 0, "malicious"),
    ]

    for folder_path, label, category_name in categories:
        if not os.path.exists(folder_path):
            print(f"Folder not found: {folder_path}")
            continue

        print(f"\n Processing folder: {category_name.upper()} — label={label}")

        files = [fn for fn in os.listdir(folder_path) if fn.lower().endswith(".json")]
        for filename in tqdm(files, desc=f"{category_name} files", unit="file"):
            file_path = os.path.join(folder_path, filename)
            data = load_json_file(file_path, filename)
            if not data:
                # Already logged the reason in load_json_file
                continue
            if not isinstance(data, dict):
                print(f"Skipped invalid JSON structure in: {filename}")
                continue

            # Collect features safely: one extractor failure won't drop the whole file
            row = {}

            # general features (pass entire top-level JSON)
            row.update(safe_call(extract_general_features, data, "extract_general_features", filename))

            # host_info, content_info, additional may be nested or absent; pass {} if missing
            host_info = data.get("host_info") or {}
            content_info = data.get("content_info") or {}
            additional = data.get("additional") or {}

            row.update(safe_call(extract_hostinfo_features, host_info, "extract_hostinfo_features", filename))
            row.update(safe_call(extract_contentinfo_features, content_info, "extract_contentinfo_features", filename))
            row.update(safe_call(extract_additional_features, additional, "extract_additional_features", filename))

            # metadata
            row["label"] = label
            row["filename"] = filename
            row["category"] = category_name

            data_rows.append(row)

    df = pd.DataFrame(data_rows)
    # Optionally fill NaNs with 0 or other value:
    if not df.empty:
        df.fillna(0, inplace=True)
    print(f"\n Dataset built with {len(df)} samples and {len(df.columns)} columns.")
    return df


if __name__ == "__main__":
    df = build_global_dataframe()
    os.makedirs("output", exist_ok=True)
    out = os.path.join("output", "phishing_dataset.csv")
    df.to_csv(out, index=False, encoding="utf-8")
    print(f"\n CSV saved to: {out}")
    print("\n DataFrame preview:")
    print(df.head(5))
