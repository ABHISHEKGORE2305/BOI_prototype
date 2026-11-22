# extractor.py
#
# Static extraction of APK artifacts with Androguard.

import logging
import re

from nexus_sec.features import ApkArtifacts
from nexus_sec.features import class_tokens
from nexus_sec.features import method_tokens

logger = logging.getLogger(__name__)

COMPONENT_TYPES = ("activity", "service", "receiver")

DEX_FILE = re.compile(r"^classes\d*\.dex$")


def extract_artifacts(apk_path):
    """Return (ApkArtifacts for the model, apk_info metadata dict)."""

    # Imported here so the API process and unit tests don't need Androguard
    from androguard.misc import AnalyzeAPK

    a, _, dx = AnalyzeAPK(apk_path)
    return artifacts_from_analysis(a, dx), apk_info(a)


def artifacts_from_analysis(a, dx):
    artifacts = ApkArtifacts()

    artifacts.permissions = set(a.get_permissions())

    components = {
        "activity": a.get_activities(),
        "service": a.get_services(),
        "receiver": a.get_receivers(),
    }
    for itemtype in COMPONENT_TYPES:
        for name in components[itemtype]:
            filters = a.get_intent_filters(itemtype, name) or {}
            artifacts.intent_actions.update(filters.get("action", []))

    # Methods include both the app's own (e.g. onServiceConnected overrides)
    # and external framework APIs it calls
    for method in dx.get_methods():
        try:
            artifacts.api_tokens |= method_tokens(method.class_name, method.name)
        except Exception:
            logger.debug("Skipping unreadable method", exc_info=True)

    for cls in dx.get_classes():
        try:
            artifacts.api_tokens |= class_tokens(cls.name)
            if not cls.is_external():
                # Interfaces / superclasses such as ServiceConnection, Binder
                for parent in [cls.extends, *cls.implements]:
                    if parent:
                        artifacts.api_tokens |= class_tokens(parent)
        except Exception:
            logger.debug("Skipping unreadable class", exc_info=True)

    for string in dx.get_strings():
        try:
            artifacts.strings.add(string.get_value())
        except Exception:
            logger.debug("Skipping unreadable string", exc_info=True)

    return artifacts


def _safe(getter, default=None):
    # Malformed manifests make individual Androguard getters raise;
    # one bad field shouldn't fail the whole scan
    try:
        return getter()
    except Exception:
        logger.debug("APK metadata field unavailable", exc_info=True)
        return default


def _certificate_info(cert):
    return {
        "subject": cert.subject.human_friendly,
        "issuer": cert.issuer.human_friendly,
        "sha256": cert.sha256_fingerprint.replace(" ", "").lower(),
        "self_signed": cert.self_signed,
        "not_after": cert["tbs_certificate"]["validity"]["not_after"].native.isoformat(),
    }


def apk_info(a):
    """Analyst-facing metadata. Shown in the UI only; never sent to the model or LLM."""

    files = _safe(a.get_files, [])

    return {
        "package": _safe(a.get_package),
        "app_name": _safe(a.get_app_name),
        "version_name": _safe(a.get_androidversion_name),
        "version_code": _safe(a.get_androidversion_code),
        "min_sdk": _safe(a.get_min_sdk_version),
        "target_sdk": _safe(a.get_target_sdk_version),
        "debuggable": _safe(
            lambda: a.get_attribute_value("application", "debuggable") == "true",
            False
        ),
        "permissions": sorted(_safe(a.get_permissions, [])),
        "component_counts": {
            "activities": len(_safe(a.get_activities, [])),
            "services": len(_safe(a.get_services, [])),
            "receivers": len(_safe(a.get_receivers, [])),
            "providers": len(_safe(a.get_providers, [])),
        },
        "dex_files": sum(1 for f in files if DEX_FILE.match(f)),
        "native_libraries": sorted(
            f for f in files if f.startswith("lib/") and f.endswith(".so")
        ),
        "signature_schemes": [
            scheme
            for scheme, check in (
                ("v1", a.is_signed_v1),
                ("v2", a.is_signed_v2),
                ("v3", a.is_signed_v3),
            )
            if _safe(check, False)
        ],
        "certificates": [
            info
            for cert in _safe(a.get_certificates, [])
            if (info := _safe(lambda cert=cert: _certificate_info(cert)))
        ],
    }
