from celery_worker import celery_app
from database import SessionLocal
from models import Task

from androguard.misc import AnalyzeAPK

from feature_builder import build_feature_vector

import joblib
import json
import shap


# Load once at startup
import google.generativeai as genai
from dotenv import load_dotenv
import os

load_dotenv()

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

GEMINI_API_KEY = os.getenv(
    "GEMINI_API_KEY"
)

genai.configure(
    api_key=GEMINI_API_KEY
)

GEMINI_MODEL = genai.GenerativeModel(
    "gemini-2.5-flash"
)

MODEL = joblib.load(
    os.path.join(BASE_DIR, "models", "malware_model.pkl")
)

with open(
    os.path.join(BASE_DIR, "models", "feature_names.json"),
    "r"
) as f:

    FEATURE_NAMES = json.load(f)

EXPLAINER = shap.TreeExplainer(MODEL)


@celery_app.task
def analyze_apk(task_id, file_path):

    db = SessionLocal()
    task = None

    try:

        task = (
            db.query(Task)
            .filter(Task.id == task_id)
            .first()
        )

        # -------------------------
        # APK Analysis
        # -------------------------

        a, d, dx = AnalyzeAPK(file_path)

        
        #permissions
        permissions = set(
            a.get_permissions()
        )

        #api calls
        api_calls = set()
        for method_analysis in dx.get_methods():

                try:

                    method = method_analysis.get_method()

                    class_name = (
                        method.get_class_name()
                        .lstrip("L")
                        .replace("/", ".")
                        .replace(";", "")
                    )

                    method_name = method.get_name()

                    full_name = (
                        f"{class_name}.{method_name}"
                    )

                    api_calls.add(method_name)

                    api_calls.add(full_name)

                except Exception:
                    continue

        #intent actions
        intent_actions = set()
        for receiver in a.get_receivers():

            filters = a.get_intent_filters(
                "receiver",
                receiver
            )

            if filters:

                actions = filters.get(
                    "action",
                    []
                )

                for action in actions:

                    intent_actions.add(
                        action
                    )

        # -------------------------
        # Feature Vector
        # -------------------------

        feature_vector = (
            build_feature_vector(
                permissions=permissions,
                api_calls=api_calls,
                intent_actions=intent_actions,
                feature_names=FEATURE_NAMES
            )
        )

        #logging and checking-----------------
        matched = 0
        for feature in FEATURE_NAMES:
            if feature_vector.iloc[0][feature] == 1:
                matched += 1

        print(
            f"Matched {matched} / {len(FEATURE_NAMES)} features"
        )
        print("Feature Vector Shape:", feature_vector.shape)
        print("Number of Features Detected:", feature_vector.sum(axis=1))



        # Safety check

        # if (
        #     feature_vector.shape[1]
        #     != len(FEATURE_NAMES)
        # ):
        #     raise Exception(
        #         f"Feature mismatch. "
        #         f"Expected {len(FEATURE_NAMES)}, "
        #         f"got {feature_vector.shape[1]}"
        #     )

        # -------------------------
        # Prediction
        # -------------------------

        malware_probability = float(
            MODEL.predict_proba(
                feature_vector
            )[0][1]
        )

        risk_score = round(
            malware_probability * 100,
            2
        )

        # -------------------------
        # SHAP
        # -------------------------
        print("staring shap----------")
        shap_values = (
            EXPLAINER.shap_values(
                feature_vector
            )
        )

        # LightGBM binary classifier
        

        if isinstance(
            shap_values,
            list
        ):
            values = shap_values[1][0]
        else:
            values = shap_values[0]

        importance = {}

        for feature, value in zip(
            feature_vector.columns,
            values
        ):

            importance[feature] = float(
                value
            )

        top_features = dict(
            sorted(
                importance.items(),
                key=lambda x: abs(
                    x[1]
                ),
                reverse=True
            )[:5]
        )
        print("Top Features:", top_features)

        #--------------------------
        #llm reasoning
        #--------------------------
        prompt = f"""
        You are a senior Android malware analyst.

        Analyze the APK based on the following information:

        Malware Risk Score:
        {risk_score:.2f}/100

        Top suspicious features:
        {top_features}

        Provide:

        1. Executive Summary
        2. Threat Analysis
        3. Potential Impact
        4. Remediation Recommendations

        Keep the report concise and professional.
        """
        print("generating llm report")
        try:
            report = GEMINI_MODEL.generate_content(
                prompt
            )
            report_text = report.text
            print("llm report generated")
        except Exception as llm_err:
            print(f"LLM report failed: {llm_err}")
            report_text = "Report generation failed."
        
        
        # -------------------------
        # Save Results
        # -------------------------

        task.status = "completed"

        task.malware_score = (risk_score)

        task.shap_data = json.dumps(top_features)

        task.llm_report = report_text

        db.commit()

    except Exception as e:

        if task:

            task.status = "failed"

            db.commit()

        raise e

    finally:

        # Clean up uploaded APK file
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except OSError:
            pass

        db.close()