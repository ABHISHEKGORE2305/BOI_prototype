# apk_builder.py
#
# Builds tiny, harmless APKs for end-to-end tests, so the suite doesn't
# depend on downloading or committing real (possibly malicious) samples.
#
# An APK is a ZIP whose AndroidManifest.xml is compiled to Android's
# binary XML format (AXML). This writes just enough of that format for
# Androguard to parse: a string pool, a namespace, and elements with
# string attributes. There is no classes.dex, so only manifest-derived
# features (permissions, intent actions) are present.

import io
import struct
import zipfile

ANDROID_NS = "http://schemas.android.com/apk/res/android"

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103

TYPE_STRING = 0x03
NO_INDEX = 0xFFFFFFFF


class _StringPool:
    def __init__(self):
        self.strings = []

    def index(self, value):
        if value not in self.strings:
            self.strings.append(value)
        return self.strings.index(value)

    def encode(self):
        offsets = b""
        data = b""
        for value in self.strings:
            offsets += struct.pack("<I", len(data))
            encoded = value.encode("utf-16-le")
            data += struct.pack("<H", len(value)) + encoded + b"\0\0"
        data += b"\0" * (-len(data) % 4)

        header_size = 28
        strings_start = header_size + len(offsets)
        size = strings_start + len(data)
        header = struct.pack(
            "<HHIIIIII",
            RES_STRING_POOL_TYPE, header_size, size,
            len(self.strings), 0, 0, strings_start, 0
        )
        return header + offsets + data


def _node(chunk_type, size, body):
    # Every XML tree node: chunk header, line number, comment (none)
    return struct.pack("<HHIII", chunk_type, 16, size, 1, NO_INDEX) + body


def _compile(element, pool, ns_index):
    """element = (tag, {attr: value}, [children]); android: prefix -> namespace."""

    tag, attrs, children = element
    encoded_attrs = b""
    for name, value in attrs.items():
        if name.startswith("android:"):
            ns, name = ns_index, name.removeprefix("android:")
        else:
            ns = NO_INDEX
        value_index = pool.index(value)
        encoded_attrs += struct.pack(
            "<IIIHBBI",
            ns, pool.index(name), value_index,
            8, 0, TYPE_STRING, value_index
        )

    start = _node(
        RES_XML_START_ELEMENT_TYPE,
        36 + len(encoded_attrs),
        struct.pack("<IIHHHHHH", NO_INDEX, pool.index(tag), 20, 20, len(attrs), 0, 0, 0)
        + encoded_attrs
    )
    inner = b"".join(_compile(child, pool, ns_index) for child in children)
    end = _node(RES_XML_END_ELEMENT_TYPE, 24, struct.pack("<II", NO_INDEX, pool.index(tag)))
    return start + inner + end


def binary_manifest(root):
    pool = _StringPool()
    prefix, uri = pool.index("android"), pool.index(ANDROID_NS)

    body = (
        _node(RES_XML_START_NAMESPACE_TYPE, 24, struct.pack("<II", prefix, uri))
        + _compile(root, pool, uri)
        + _node(RES_XML_END_NAMESPACE_TYPE, 24, struct.pack("<II", prefix, uri))
    )
    content = pool.encode() + body
    return struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(content)) + content


def build_apk(package, permissions=(), receiver_actions=()):
    """Return the bytes of a minimal APK declaring the given manifest entries."""

    application_children = []
    if receiver_actions:
        application_children.append(
            ("receiver", {"android:name": f"{package}.Receiver"}, [
                ("intent-filter", {}, [
                    ("action", {"android:name": action}, [])
                    for action in receiver_actions
                ]),
            ])
        )

    manifest = (
        "manifest",
        {"package": package, "android:versionName": "1.0"},
        [
            ("uses-sdk", {"android:minSdkVersion": "21"}, []),
            *[("uses-permission", {"android:name": p}, []) for p in permissions],
            ("application", {"android:label": "Test"}, application_children),
        ],
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("AndroidManifest.xml", binary_manifest(manifest))
    return buffer.getvalue()
