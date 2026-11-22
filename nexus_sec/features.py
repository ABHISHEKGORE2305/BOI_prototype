# features.py
#
# Maps static artifacts extracted from an APK onto the Drebin-215 feature
# schema the model was trained on.
#
# The schema mixes several naming styles, so each feature is matched
# according to its category (datasets/dataset-features-categories.csv):
#
#   Manifest Permission  SEND_SMS                   short permission name
#   Intent               android.intent.action.X    manifest filter or DEX string
#   Commands signature   chmod, /system/bin         substring of a DEX string
#   API call signature   transact                   method name
#                        DexClassLoader             short class name
#                        android.os.Binder          qualified class name
#                        TelephonyManager.getDeviceId   Class.method
#                        Ljava.lang.Class.forName   L-prefixed qualified method
#                        HttpGet.init               constructor (<init>)

import csv
import re
from dataclasses import dataclass
from dataclasses import field

import pandas as pd

PERMISSION = "Manifest Permission"
API_CALL = "API call signature"
INTENT = "Intent"
COMMAND = "Commands signature"

CATEGORY_KEYS = {
    PERMISSION: "permissions",
    API_CALL: "api_calls",
    INTENT: "intents",
    COMMAND: "commands",
}


@dataclass
class ApkArtifacts:
    # Full permission names declared in the manifest
    permissions: set = field(default_factory=set)
    # Actions from intent filters of any manifest component
    intent_actions: set = field(default_factory=set)
    # Class / method name tokens referenced in bytecode (see method_tokens)
    api_tokens: set = field(default_factory=set)
    # String constants from the DEX files
    strings: set = field(default_factory=set)


def load_feature_categories(path):
    with open(path, newline="") as f:
        return {
            row[0]: row[1]
            for row in csv.reader(f)
            if len(row) >= 2
        }


def class_tokens(descriptor):
    """'Landroid/telephony/SmsManager;' -> {'android.telephony.SmsManager', 'SmsManager'}"""

    name = descriptor
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    dotted = name.replace("/", ".")
    short = dotted.rsplit(".", 1)[-1]
    return {dotted, short}


def method_tokens(class_descriptor, method_name):
    """Every spelling of a method reference that appears in the Drebin schema."""

    name = "init" if method_name == "<init>" else method_name
    tokens = {name}
    for cls in class_tokens(class_descriptor):
        tokens.add(cls)
        tokens.add(f"{cls}.{name}")
        if "." in cls:
            tokens.add(f"L{cls}.{name}")
    return tokens


def _command_pattern(command):
    # Word commands ("mount") must not match inside other words ("amount");
    # paths ("/system/bin") are plain substrings.
    if re.fullmatch(r"\w+", command):
        return re.compile(rf"\b{re.escape(command)}\b")
    return re.compile(re.escape(command))


def match_features(artifacts, feature_names, categories):
    """Return the matched features grouped by category key."""

    permission_names = {p.rsplit(".", 1)[-1] for p in artifacts.permissions}
    strings_blob = "\n".join(artifacts.strings)

    matched = {key: [] for key in CATEGORY_KEYS.values()}
    matched["other"] = []

    for feature in feature_names:
        category = categories.get(feature)

        if category == PERMISSION:
            hit = feature in permission_names
        elif category == INTENT:
            hit = (
                feature in artifacts.intent_actions
                or feature in artifacts.strings
            )
        elif category == COMMAND:
            hit = bool(_command_pattern(feature).search(strings_blob))
        else:
            # API call signatures also contain a few permission names
            # (SET_ALARM) and intent constants used in code
            hit = (
                feature in artifacts.api_tokens
                or feature in permission_names
                or feature in artifacts.strings
                or feature in artifacts.intent_actions
            )

        if hit:
            matched[CATEGORY_KEYS.get(category, "other")].append(feature)

    if not matched["other"]:
        del matched["other"]

    return matched


def build_feature_vector(matched, feature_names):
    """One-row DataFrame with columns in model order (1 = present)."""

    present = {f for group in matched.values() for f in group}

    return pd.DataFrame(
        [[1 if f in present else 0 for f in feature_names]],
        columns=feature_names
    )
