from types import SimpleNamespace

from nexus_sec.extractor import apk_info
from nexus_sec.extractor import artifacts_from_analysis


class FakeAPK:
    def get_permissions(self):
        return ["android.permission.SEND_SMS"]

    def get_activities(self):
        return ["com.app.Main"]

    def get_services(self):
        return ["com.app.Svc"]

    def get_receivers(self):
        return ["com.app.Boot"]

    def get_providers(self):
        return []

    def get_intent_filters(self, itemtype, name):
        return {
            "activity": {"action": ["android.intent.action.MAIN"]},
            "service": {"action": ["android.intent.action.SEND"]},
            "receiver": {"action": ["android.intent.action.BOOT_COMPLETED"]},
        }[itemtype]

    def get_package(self):
        return "com.app"

    def get_app_name(self):
        return "App"

    def get_androidversion_name(self):
        return "1.0"

    def get_androidversion_code(self):
        return "1"

    def get_min_sdk_version(self):
        return "21"

    def get_target_sdk_version(self):
        return "34"

    def get_attribute_value(self, tag, attribute):
        return "true"

    def get_files(self):
        return ["classes.dex", "classes2.dex", "lib/arm64-v8a/libx.so", "res/a.xml"]

    def is_signed_v1(self):
        return True

    def is_signed_v2(self):
        return True

    def is_signed_v3(self):
        raise ValueError("malformed signing block")

    def get_certificates(self):
        return []


class FakeClass:
    def __init__(self, name, external, extends=None, implements=()):
        self.name = name
        self._external = external
        self.extends = extends
        self.implements = list(implements)

    def is_external(self):
        return self._external


class FakeAnalysis:
    def get_methods(self):
        return [
            SimpleNamespace(class_name="Ljava/lang/Class;", name="forName"),
            SimpleNamespace(class_name="Lcom/app/Conn;", name="onServiceConnected"),
        ]

    def get_classes(self):
        return [
            FakeClass(
                "Lcom/app/Conn;",
                external=False,
                extends="Ljava/lang/Object;",
                implements=["Landroid/content/ServiceConnection;"],
            ),
            FakeClass("Ldalvik/system/DexClassLoader;", external=True),
        ]

    def get_strings(self):
        return [SimpleNamespace(get_value=lambda: "chmod 777 x")]


def test_artifacts_from_analysis():
    artifacts = artifacts_from_analysis(FakeAPK(), FakeAnalysis())

    assert artifacts.permissions == {"android.permission.SEND_SMS"}
    # Intent filters are read from every component type, not just receivers
    assert artifacts.intent_actions == {
        "android.intent.action.MAIN",
        "android.intent.action.SEND",
        "android.intent.action.BOOT_COMPLETED",
    }
    assert {
        "Ljava.lang.Class.forName",
        "onServiceConnected",
        "ServiceConnection",
        "DexClassLoader",
    } <= artifacts.api_tokens
    assert artifacts.strings == {"chmod 777 x"}


def test_apk_info_tolerates_failing_fields():
    info = apk_info(FakeAPK())

    assert info["package"] == "com.app"
    assert info["target_sdk"] == "34"
    assert info["debuggable"] is True
    assert info["dex_files"] == 2
    assert info["native_libraries"] == ["lib/arm64-v8a/libx.so"]
    # is_signed_v3 raised; the scan still produces metadata
    assert info["signature_schemes"] == ["v1", "v2"]
    assert info["component_counts"]["receivers"] == 1
