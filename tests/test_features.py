from nexus_sec.features import ApkArtifacts
from nexus_sec.features import build_feature_vector
from nexus_sec.features import class_tokens
from nexus_sec.features import match_features
from nexus_sec.features import method_tokens


def matched_set(matched):
    return {f for group in matched.values() for f in group}


def test_every_schema_feature_has_a_category(feature_names, categories):
    assert len(feature_names) == 215
    assert [f for f in feature_names if f not in categories] == []


def test_class_tokens():
    assert class_tokens("Landroid/telephony/SmsManager;") == {
        "android.telephony.SmsManager",
        "SmsManager",
    }


def test_method_tokens_cover_schema_spellings():
    tokens = method_tokens("Ljava/lang/Class;", "forName")
    assert "Ljava.lang.Class.forName" in tokens
    assert "forName" in tokens

    assert "TelephonyManager.getDeviceId" in method_tokens(
        "Landroid/telephony/TelephonyManager;", "getDeviceId"
    )
    assert "HttpGet.init" in method_tokens(
        "Lorg/apache/http/client/methods/HttpGet;", "<init>"
    )


def test_api_call_features_match(feature_names, categories):
    artifacts = ApkArtifacts(
        api_tokens=(
            method_tokens("Ljava/lang/Class;", "forName")
            | method_tokens("Landroid/content/Context;", "registerReceiver")
            | method_tokens("Landroid/telephony/TelephonyManager;", "getDeviceId")
            | method_tokens("Ldalvik/system/DexClassLoader;", "<init>")
            | method_tokens("Ljava/lang/Runtime;", "exec")
            | class_tokens("Landroid/os/Binder;")
        )
    )

    found = set(match_features(artifacts, feature_names, categories)["api_calls"])

    assert {
        "Ljava.lang.Class.forName",
        "Landroid.content.Context.registerReceiver",
        "TelephonyManager.getDeviceId",
        "DexClassLoader",
        "Runtime.exec",
        "android.os.Binder",
        "Binder",
    } <= found


def test_permissions_match_by_short_name(feature_names, categories):
    artifacts = ApkArtifacts(
        permissions={
            "android.permission.SEND_SMS",
            "android.permission.READ_PHONE_STATE",
            "com.android.alarm.permission.SET_ALARM",
        }
    )

    matched = match_features(artifacts, feature_names, categories)

    assert {"SEND_SMS", "READ_PHONE_STATE"} <= set(matched["permissions"])
    # SET_ALARM is categorised as an API call in the Drebin schema
    assert "SET_ALARM" in matched["api_calls"]


def test_intents_from_manifest_and_code_strings(feature_names, categories):
    artifacts = ApkArtifacts(
        intent_actions={"android.intent.action.BOOT_COMPLETED"},
        strings={"android.intent.action.SCREEN_OFF"},
    )

    matched = match_features(artifacts, feature_names, categories)

    assert {
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.SCREEN_OFF",
    } <= set(matched["intents"])


def test_commands_match_as_words_or_paths(feature_names, categories):
    artifacts = ApkArtifacts(
        strings={"chmod 777 /data/local/tmp/x", "/system/bin/sh", "total amount"}
    )

    commands = match_features(artifacts, feature_names, categories)["commands"]

    assert set(commands) == {"chmod", "/system/bin"}


def test_empty_artifacts_match_nothing(feature_names, categories):
    matched = match_features(ApkArtifacts(), feature_names, categories)
    assert matched_set(matched) == set()


def test_feature_vector_follows_schema_order(feature_names, categories):
    artifacts = ApkArtifacts(permissions={"android.permission.SEND_SMS"})
    matched = match_features(artifacts, feature_names, categories)

    vector = build_feature_vector(matched, feature_names)

    assert list(vector.columns) == feature_names
    assert vector.shape == (1, 215)
    assert vector.iloc[0]["SEND_SMS"] == 1
    assert int(vector.values.sum()) == 1
