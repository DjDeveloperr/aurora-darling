#!/usr/bin/env python3
"""Build the reviewed objc4-876 graph with Apple Clang and package a strict artifact."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile


OBJC_COMMIT = "c3f002513d195ef564f3c7e9496c2606360e144a"
OBJC_TREE = "a838e232bd2869275f585ca0f7281fc04c93d49c"
PATCH_INPUTS = {
    "0001-objc4-876-darling-source-compat.patch.gz": {
        "stored_sha256": "bb786545a49c4516f2ea0732432d848f4a6e119855eade39cc8e40cc4d7f5bdd",
        "content_sha256": "34ebf2142aa1dcee7eac7104cfd6bed64f7cad489bb425f105218a3de670199d",
        "gzip": True,
    },
    "0002-objc4-876-darling-cmake-graph.patch": {
        "stored_sha256": "0a06fa2c04bd1e32aafc2b5f9ee121b801e119f34d78df62655e13c60683dd76",
        "content_sha256": "0a06fa2c04bd1e32aafc2b5f9ee121b801e119f34d78df62655e13c60683dd76",
        "gzip": False,
    },
    "0003-objc4-876-full-dyld-priv.patch": {
        "stored_sha256": "1548fbcd4f74f2a7d98e9596a3ba3a69f31ded7e3edfcf05ac48bbf4ad09ef58",
        "content_sha256": "1548fbcd4f74f2a7d98e9596a3ba3a69f31ded7e3edfcf05ac48bbf4ad09ef58",
        "gzip": False,
    },
}
DYLD_SPI_INPUT = {
    "name": "objc4-876-dyld-spi.patch.gz",
    "stored_sha256": "4b4a18e72efc0d773c88dd8263936c802f8e3727ecc93a750e448eea4270a704",
    "content_sha256": "bd02eda56c2a36fac96667a083455f10210b8aeb1b8ae01396580524a97576c0",
}
TARGET = "arm64e-apple-macos13.0"
MIN_OS = "13.0"
SDK_NAME = "macosx15.5"
SDK_VERSION = "15.5"
XCODE_VERSION = ("Xcode 16.4", "Build version 16F6")
PUBLIC_HEADERS_PROVENANCE_SHA256 = "6e1753712d57bf6b96326f30944f42bd69fcf31df445a0039c0739b191ee0edc"
LOCAL_COMPAT_PROVENANCE_SHA256 = "9e590cab1e99aa00474e78683c6dbf85b3e90fb2fa2961829a45dfb83712036c"
HEADER_DEPENDENCY_MANIFEST_SHA256 = "7338a0008023427cf56f66c0c48eb45660923028ffe5883d5093116d114f94fa"
HEADER_PROBE_CONTEXT_SHA256 = "6ade7b8d4afbb127e6f74817482374583f200ca6296ab3470bab9fa3fe648d07"
DYLD_BRIDGEOS_DECLARATIONS = (
    "dyld_get_active_platform", "dyld_get_base_platform",
    "dyld_is_simulator_platform", "dyld_sdk_at_least", "dyld_minos_at_least",
    "dyld_program_sdk_at_least", "dyld_program_minos_at_least",
    "dyld_get_image_versions",
)
DYLD_BRIDGEOS_ARGUMENTS = (
    "macos(10.14)", "ios(12.0)", "watchos(5.0)", "tvos(12.0)", "bridgeos(3.0)",
)
PUBLIC_HEADERS = {
    "mach-o/dyld_priv.h": {
        "repository": "https://github.com/apple-oss-distributions/dyld.git",
        "tag": "dyld-1066.10",
        "commit": "3e5ba1a2d04c3a221eab66b99e0e0dd90a470150",
        "path": "include/mach-o/dyld_priv.h",
        "sha256": "82eb5bcf0dd6f8fa1305c69110b2e7c333b74375433d8216d7a29452a7374ac8",
        "stored_path": "mach-o/dyld_priv.h.gz",
        "stored_compression": "gzip",
        "stored_sha256": "c26fbc499831bdf43b5158462438bf83a138d6baf694b7e14e87e3966d3ac502",
        "license": "APSL-2.0",
        "materialization": {
            "declarations": list(DYLD_BRIDGEOS_DECLARATIONS),
            "normalized_sha256": "9f8ce4c1e3e1ab2d34d3d3af3a3d7c77003455a76e69c16940b7e57b06d0c615",
            "platform_scope": "macos-only",
            "removal_count": 8,
            "rule": "remove-final-bridgeos-3.0-from-four-platform-api-available",
        },
        "includes": ["assert.h", "stdbool.h", "unistd.h", "Availability.h",
                     "TargetConditionals.h", "mach-o/dyld.h", "uuid/uuid.h"],
        "user_mode_active_includes": ["assert.h", "stdbool.h", "unistd.h",
                                      "Availability.h", "TargetConditionals.h",
                                      "mach-o/dyld.h", "uuid/uuid.h"],
    },
    "sys/reason.h": {
        "repository": "https://github.com/apple-oss-distributions/xnu.git",
        "tag": "xnu-8796.141.3",
        "commit": "1b191cb58250d0705d8a51287127505aa4bc0789",
        "path": "bsd/sys/reason.h",
        "sha256": "782540658b7d4af1fb7278de7868874e374db6c35af5be9756a19ee4b6983cb3",
        "stored_path": "sys/reason.h",
        "stored_compression": "none",
        "stored_sha256": "782540658b7d4af1fb7278de7868874e374db6c35af5be9756a19ee4b6983cb3",
        "license": "APSL-2.0",
        "includes": ["stdint.h", "kern/kern_cdata.h", "os/refcnt.h", "kern/locks.h"],
        "user_mode_active_includes": ["stdint.h"],
    }
}
_METADATA_ROOT = Path(__file__).resolve().parents[1] / "objc876"
PUBLIC_HEADERS = json.loads((_METADATA_ROOT / "PUBLIC_HEADERS.json").read_text())["headers"]
_LOCAL_COMPAT_DOCUMENT = json.loads((_METADATA_ROOT / "LOCAL_COMPAT_HEADERS.json").read_text())
LOCAL_COMPAT_HEADERS = _LOCAL_COMPAT_DOCUMENT["headers"]
ALL_HEADER_POLICIES = {**PUBLIC_HEADERS, **LOCAL_COMPAT_HEADERS}
_HEADER_PROBE_DOCUMENT = json.loads((_METADATA_ROOT / "HEADER_PROBE_CONTEXT.json").read_text())
HEADER_PROBE_CONTEXT = _HEADER_PROBE_DOCUMENT["headers"]
OFFICIAL_LICENSE_POLICY = {
    "Block_private.h": ("APPLE_LLVM_LICENSE_HEADER placeholder; license not asserted", False),
    "os/base_private.h": ("Apache-2.0", True),
    "os/lock_private.h": ("Apache-2.0", True),
    "os/variant_private.h": ("Apache-2.0", True),
}
PATCH_COMPAT_HEADERS = {
    "TargetConditionals.h", "mach-o/dyld.h", "mach-o/dyld_priv.h",
    "objc-probes.h", "ptrauth.h",
}
COMPAT_INCLUDE_NEXT = {
    "TargetConditionals.h": "TargetConditionals.h",
    "mach-o/dyld.h": "mach-o/dyld.h",
    "mach-o/dyld_priv.h": "mach-o/dyld_priv.h",
    "ptrauth.h": "ptrauth.h",
}
HEADER_PROBE_NAMES = tuple(sorted(PATCH_COMPAT_HEADERS | set(ALL_HEADER_POLICIES)))
FULL_DYLD_PRIV_DEFINE = "-DOBJC_USE_FULL_DYLD_PRIV_1066=1"
RUNTIME_SOURCES = (
    "maptable.mm", "hashtable2.mm", "NSObject.mm", "objc-accessors.mm",
    "objc-auto.mm", "objc-block-trampolines.mm", "objc-cache.mm",
    "objc-class.mm", "objc-errors.mm", "objc-exception.mm", "objc-file.mm",
    "objc-initialize.mm", "objc-layout.mm", "objc-loadmethod.mm", "objc-load.mm",
    "objc-lockdebug.mm", "objc-magicsel.m", "objc-opt.mm", "objc-os.mm",
    "objc-references.mm", "objc-runtime.mm", "objc-runtime-new.mm", "objc-sel.mm",
    "objc-sync.mm", "objc-typeencoding.mm", "objc-weak.mm", "objc-zalloc.mm",
    "Object.mm", "Protocol.mm", "objc-blocktramps-arm64.s", "objc-sel-table.s",
    "retain-release-helpers-arm64.s", "Messengers.subproj/objc-msg-arm64.s",
)
ARTIFACT_FILES = {
    "libobjc.A.dylib", "build-argv.json", "provenance.json", "SHA256SUMS"
}
OLD_FEATURE_PROBE_SOURCE = (
    "#include <stdint.h>\n"
    "#include \"objc-ptrauth.h\"\n"
    "#if !__has_feature(ptrauth_calls)\n#error ptrauth_calls_required\n#endif\n"
    "#if !__has_feature(ptrauth_restricted_intptr_qualifier)\n"
    "#error restricted_intptr_required\n#endif\n"
    "uintptr_t ptrauth_class_rx_enforce auroraClassRX;\n"
    "uintptr_t ptrauth_trampoline_textSegment auroraTextSegment;\n"
    "int auroraRestrictedPtrauthControl(void) { return 0; }\n"
)
FEATURE_PROBE_SOURCE = (
    "#include <stdint.h>\n"
    "#include <ptrauth.h>\n"
    "#if !__has_feature(ptrauth_calls)\n#error ptrauth_calls_required\n#endif\n"
    "#if !__has_feature(ptrauth_restricted_intptr_qualifier)\n"
    "#error restricted_intptr_required\n#endif\n"
    "uintptr_t __ptrauth_restricted_intptr("
    "ptrauth_key_process_dependent_data, 1, 0x47f5) auroraClassRX;\n"
    "uintptr_t __ptrauth_restricted_intptr("
    "ptrauth_key_process_dependent_data, 1, "
    "ptrauth_string_discriminator(\"TrampolinePointerWrapper::TrampolinePointers::textSegment\")) "
    "auroraTextSegment;\n"
    "int auroraRestrictedPtrauthControl(void) { return 0; }\n"
)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def output(argv, cwd=None):
    return subprocess.check_output(argv, cwd=cwd, text=True, stderr=subprocess.STDOUT).strip()


def run(argv, cwd=None):
    subprocess.run(argv, cwd=cwd, check=True)


def decoded_input(path, compressed):
    data = path.read_bytes()
    return gzip.decompress(data) if compressed else data


def normalized_patch(data):
    result = []
    for line in data.splitlines(keepends=True):
        if line.startswith(b"+") and not line.startswith(b"+++"):
            newline = b"\n" if line.endswith(b"\n") else b""
            body = line[1:].rstrip(b"\r\n").rstrip(b" \t")
            while body.startswith(b" \t"):
                body = body[1:]
            line = b"+" + body + newline
        result.append(line)
    return b"".join(result)


def verify_inputs(patch_dir):
    observed = {"port_patches": {}, "dyld_spi": {}}
    for name, policy in PATCH_INPUTS.items():
        path = patch_dir / name
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("required patch is not a regular file: " + name)
        stored = sha256(path)
        content = hashlib.sha256(decoded_input(path, policy["gzip"])).hexdigest()
        if stored != policy["stored_sha256"] or content != policy["content_sha256"]:
            raise RuntimeError("port patch hash mismatch: " + name)
        observed["port_patches"][name] = {
            "stored_sha256": stored, "content_sha256": content
        }
    dyld_path = patch_dir / DYLD_SPI_INPUT["name"]
    if not dyld_path.is_file() or dyld_path.is_symlink():
        raise RuntimeError("dyld SPI contract is not a regular file")
    stored = sha256(dyld_path)
    content = hashlib.sha256(gzip.decompress(dyld_path.read_bytes())).hexdigest()
    if stored != DYLD_SPI_INPUT["stored_sha256"] or content != DYLD_SPI_INPUT["content_sha256"]:
        raise RuntimeError("dyld SPI contract hash mismatch")
    observed["dyld_spi"] = {"stored_sha256": stored, "content_sha256": content}
    dependency_path = patch_dir / "OBJC876_HEADERS.json"
    if (not dependency_path.is_file() or dependency_path.is_symlink() or
            sha256(dependency_path) != HEADER_DEPENDENCY_MANIFEST_SHA256):
        raise RuntimeError("objc876 dependency manifest mismatch")
    dependency = json.loads(dependency_path.read_text(encoding="utf-8"))
    if (dependency.get("schema") != "aurora_objc876_header_dependencies_v1" or
            dependency.get("translation_unit_count") != 33 or
            dependency.get("non_source_header_count") != 890 or
            dependency.get("closure_classes", {}).get("darling_low_level_compat_headers") !=
            ["CrashReporterClient.h", "os/feature_private.h", "sandbox/private.h"]):
        raise RuntimeError("objc876 dependency manifest content mismatch")
    observed["dependency_manifest"] = {
        "sha256": HEADER_DEPENDENCY_MANIFEST_SHA256,
        "translation_unit_count": 33,
        "non_source_header_count": 890,
    }
    probe_path = patch_dir / "HEADER_PROBE_CONTEXT.json"
    if (not probe_path.is_file() or probe_path.is_symlink() or
            sha256(probe_path) != HEADER_PROBE_CONTEXT_SHA256):
        raise RuntimeError("header probe context manifest mismatch")
    probe = json.loads(probe_path.read_text(encoding="utf-8"))
    if (probe.get("schema") != "aurora_objc876_header_probe_context_v1" or
            probe.get("header_count") != len(ALL_HEADER_POLICIES) or
            probe.get("production_source_count") != 33 or
            probe.get("headers") != HEADER_PROBE_CONTEXT or
            set(HEADER_PROBE_CONTEXT) != set(ALL_HEADER_POLICIES)):
        raise RuntimeError("header probe context content mismatch")
    for name, context in HEADER_PROBE_CONTEXT.items():
        if (context.get("probe_prelude") not in ([], ["pthread.h"]) or
                not context.get("justification")):
            raise RuntimeError("header probe prelude policy mismatch: " + name)
    observed["header_probe_context"] = {
        "sha256": HEADER_PROBE_CONTEXT_SHA256,
        "header_count": len(HEADER_PROBE_CONTEXT),
        "production_source_count": 33,
    }
    return observed


def enumerate_directory(root):
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise RuntimeError("audited root is not a real directory")
    files = set()
    directories = set()
    pending = [(root, Path())]
    while pending:
        directory, relative = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                child_relative = relative / entry.name
                info = entry.stat(follow_symlinks=False)
                name = child_relative.as_posix()
                if stat.S_ISLNK(info.st_mode):
                    raise RuntimeError("symlink in audited tree: " + name)
                if stat.S_ISDIR(info.st_mode):
                    directories.add(name)
                    pending.append((Path(entry.path), child_relative))
                elif stat.S_ISREG(info.st_mode):
                    files.add(name)
                else:
                    raise RuntimeError("non-regular entry in audited tree: " + name)
    return {"files": files, "directories": directories}


def verify_public_headers(public_root):
    provenance_path = public_root.parent / "PUBLIC_HEADERS.json"
    if (not provenance_path.is_file() or provenance_path.is_symlink() or
            sha256(provenance_path) != PUBLIC_HEADERS_PROVENANCE_SHA256):
        raise RuntimeError("public-header provenance mismatch")
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    if provenance.get("schema") != "aurora_objc876_public_headers_v1":
        raise RuntimeError("public-header provenance schema mismatch")
    if provenance.get("headers") != PUBLIC_HEADERS:
        raise RuntimeError("public-header provenance content mismatch")
    if any(not policy.get("repository", "").startswith(
            "https://github.com/apple-oss-distributions/") for policy in PUBLIC_HEADERS.values()):
        raise RuntimeError("official-header provenance class mismatch")
    for name, (license_name, asserted) in OFFICIAL_LICENSE_POLICY.items():
        policy = PUBLIC_HEADERS.get(name, {})
        if (policy.get("license") != license_name or
                policy.get("license_asserted") is not asserted):
            raise RuntimeError("official-header license metadata mismatch: " + name)
    local_path = public_root.parent / "LOCAL_COMPAT_HEADERS.json"
    if (not local_path.is_file() or local_path.is_symlink() or
            sha256(local_path) != LOCAL_COMPAT_PROVENANCE_SHA256):
        raise RuntimeError("local-compat provenance mismatch")
    local = json.loads(local_path.read_text(encoding="utf-8"))
    if (local.get("schema") != "aurora_objc876_local_compat_headers_v1" or
            local.get("repository") != "https://github.com/DjDeveloperr/aurora-darling.git" or
            local.get("commit") != "cade924e69d2eb36899bdff31474a73f4655abfd" or
            local.get("repository_license") != {
                "spdx": "GPL-3.0-only", "path": "LICENSE",
                "sha256": "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903"} or
            local.get("headers") != LOCAL_COMPAT_HEADERS or
            set(LOCAL_COMPAT_HEADERS) != {"CrashReporterClient.h", "os/feature_private.h",
                                          "sandbox/private.h"}):
        raise RuntimeError("local-compat provenance content mismatch")
    if any(not policy.get("semantics") or not policy.get("license")
           for policy in LOCAL_COMPAT_HEADERS.values()):
        raise RuntimeError("local-compat semantics or license missing")
    if any(policy.get("license") != "GPL-3.0-only" or
           policy.get("license_source") != "repository-root LICENSE at pinned commit" or
           policy.get("license_status") !=
           "governing repository license; file has no standalone license notice"
           for policy in LOCAL_COMPAT_HEADERS.values()):
        raise RuntimeError("local-compat governing license mismatch")
    observed = {}
    entries = enumerate_directory(public_root)
    stored_files = {policy["stored_path"] for policy in ALL_HEADER_POLICIES.values()}
    stored_directories = {str(parent) for name in stored_files
                          for parent in Path(name).parents if str(parent) != "."}
    if entries != {"files": stored_files, "directories": stored_directories}:
        raise RuntimeError("public-header root is not the exact allowlist")
    for name, policy in ALL_HEADER_POLICIES.items():
        path = public_root / policy["stored_path"]
        stored_hash = sha256(path)
        if not path.is_file() or path.is_symlink() or stored_hash != policy["stored_sha256"]:
            raise RuntimeError("public-header input mismatch: " + name)
        stored = path.read_bytes()
        content = gzip.decompress(stored) if policy["stored_compression"] == "gzip" else stored
        content_hash = hashlib.sha256(content).hexdigest()
        if content_hash != policy["sha256"]:
            raise RuntimeError("public-header decoded content mismatch: " + name)
        includes = re.findall(r'^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]',
                              content.decode("utf-8"), re.MULTILINE)
        if includes != policy["includes"]:
            raise RuntimeError("public-header dependency list mismatch: " + name)
        provenance_class = ("darling_low_level_compat" if name in LOCAL_COMPAT_HEADERS
                            else "official_apple_oss")
        observed[name] = {**policy, "sha256": content_hash,
                          "stored_sha256": stored_hash,
                          "provenance_class": provenance_class}
    return observed


def normalize_dyld_priv_for_macos(content):
    text = content.decode("utf-8")
    needle = ", bridgeos(3.0)"
    if text.count(needle) != len(DYLD_BRIDGEOS_DECLARATIONS):
        raise RuntimeError("dyld bridgeOS availability count mismatch")
    seen = []
    output_lines = []
    for line in text.splitlines(keepends=True):
        if needle not in line:
            output_lines.append(line)
            continue
        names = [name for name in DYLD_BRIDGEOS_DECLARATIONS
                 if re.search(r'\b' + re.escape(name) + r'\s*\(', line)]
        if len(names) != 1 or "__API_AVAILABLE(" not in line:
            raise RuntimeError("dyld bridgeOS declaration context mismatch")
        name = names[0]
        marker = "__API_AVAILABLE("
        start = line.index(marker) + len(marker)
        depth = 1
        end = start
        while end < len(line) and depth:
            if line[end] == "(":
                depth += 1
            elif line[end] == ")":
                depth -= 1
            end += 1
        if depth != 0:
            raise RuntimeError("dyld bridgeOS availability nesting mismatch")
        body = line[start:end - 1]
        arguments = []
        argument_start = 0
        argument_depth = 0
        for index, character in enumerate(body):
            if character == "(":
                argument_depth += 1
            elif character == ")":
                argument_depth -= 1
                if argument_depth < 0:
                    raise RuntimeError("dyld bridgeOS argument nesting mismatch")
            elif character == "," and argument_depth == 0:
                arguments.append(body[argument_start:index].strip())
                argument_start = index + 1
        if argument_depth != 0:
            raise RuntimeError("dyld bridgeOS argument nesting mismatch")
        arguments.append(body[argument_start:].strip())
        if tuple(arguments) != DYLD_BRIDGEOS_ARGUMENTS or not body.endswith(needle[2:]):
            raise RuntimeError("dyld bridgeOS platform list mismatch")
        normalized_body = body[:-len(needle)]
        output_lines.append(line[:start] + normalized_body + line[end - 1:])
        seen.append(name)
    if tuple(seen) != DYLD_BRIDGEOS_DECLARATIONS:
        raise RuntimeError("dyld bridgeOS declaration order mismatch")
    normalized = "".join(output_lines).encode("utf-8")
    expected = content.replace(needle.encode("utf-8"), b"")
    if normalized != expected:
        raise RuntimeError("dyld bridgeOS normalization changed unrelated bytes")
    expected_hash = PUBLIC_HEADERS["mach-o/dyld_priv.h"]["materialization"]["normalized_sha256"]
    if hashlib.sha256(normalized).hexdigest() != expected_hash:
        raise RuntimeError("dyld bridgeOS normalized hash mismatch")
    return normalized


def normalize_private_availability_for_macos(name, content):
    if name not in PUBLIC_HEADERS:
        return content
    policy = PUBLIC_HEADERS[name]
    materialization = policy.get("materialization", {})
    rules = materialization.get("private_platform_removals", [])
    if not rules:
        return content
    text = content.decode("utf-8")
    original = text
    for rule in rules:
        needle = rule["needle"]
        if text.count(needle) != rule["count"] or len(rule["contexts"]) != rule["count"]:
            raise RuntimeError("private availability count mismatch: " + name)
        occurrence_positions = [match.start() for match in re.finditer(re.escape(needle), text)]
        context_positions = []
        for context in rule["contexts"]:
            if text.count(context) != 1:
                raise RuntimeError("private availability context mismatch: " + name)
            context_positions.append(text.index(context))
        if occurrence_positions != sorted(occurrence_positions) or context_positions != sorted(context_positions):
            raise RuntimeError("private availability context order mismatch: " + name)
        if any(abs(occurrence - context) > 2048
               for occurrence, context in zip(occurrence_positions, context_positions)):
            raise RuntimeError("private availability context distance mismatch: " + name)
        text = text.replace(needle, rule["replacement"])
    if materialization.get("require_no_private_platform") and "bridgeos" in text:
        raise RuntimeError("unexpected private platform remains: " + name)
    normalized = text.encode("utf-8")
    expected = original
    for rule in rules:
        expected = expected.replace(rule["needle"], rule["replacement"])
    if normalized != expected.encode("utf-8"):
        raise RuntimeError("private availability normalization changed unrelated bytes: " + name)
    if hashlib.sha256(normalized).hexdigest() != materialization["normalized_sha256"]:
        raise RuntimeError("private availability normalized hash mismatch: " + name)
    return normalized


def materialize_public_headers(public_root, output_root):
    verify_public_headers(public_root)
    if output_root.exists():
        raise RuntimeError("materialized public-header root already exists")
    for name, policy in ALL_HEADER_POLICIES.items():
        stored = (public_root / policy["stored_path"]).read_bytes()
        content = gzip.decompress(stored) if policy["stored_compression"] == "gzip" else stored
        if name == "mach-o/dyld_priv.h":
            content = normalize_dyld_priv_for_macos(content)
        else:
            content = normalize_private_availability_for_macos(name, content)
        target = output_root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    entries = enumerate_directory(output_root)
    logical_files = set(ALL_HEADER_POLICIES)
    logical_directories = {str(parent) for name in logical_files
                           for parent in Path(name).parents if str(parent) != "."}
    if entries != {"files": logical_files, "directories": logical_directories}:
        raise RuntimeError("materialized public-header tree mismatch")
    for name, policy in ALL_HEADER_POLICIES.items():
        expected_hash = policy.get("materialization", {}).get("normalized_sha256", policy["sha256"])
        if sha256(output_root / name) != expected_hash:
            raise RuntimeError("materialized public-header hash mismatch: " + name)
    return output_root


def full_dyld_priv_flags(public_headers):
    dyld = public_headers.get("mach-o/dyld_priv.h")
    expected = PUBLIC_HEADERS["mach-o/dyld_priv.h"]
    if (not dyld or dyld.get("sha256") != expected["sha256"] or
            dyld.get("stored_sha256") != expected["stored_sha256"] or
            dyld.get("commit") != expected["commit"] or dyld.get("tag") != expected["tag"]):
        raise RuntimeError("full dyld private header is not the verified 1066.10 input")
    return [FULL_DYLD_PRIV_DEFINE]


def include_search_roots(source, build, public_root, sdk):
    return (
        build / "include", source / "runtime/compat", source / "runtime",
        public_root, sdk / "usr/include",
    )


def resolve_header(name, roots, after=None):
    start = 0 if after is None else roots.index(after) + 1
    for root in roots[start:]:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def verify_source(source):
    if output(["git", "-C", str(source), "rev-parse", "HEAD"]) != OBJC_COMMIT:
        raise RuntimeError("unexpected objc4 commit")
    if output(["git", "-C", str(source), "rev-parse", "HEAD^{tree}"]) != OBJC_TREE:
        raise RuntimeError("unexpected objc4 tree")
    for name in RUNTIME_SOURCES:
        if not (source / "runtime" / name).is_file():
            raise RuntimeError("missing production source: " + name)


def apply_patches(source, patch_dir):
    with tempfile.TemporaryDirectory(prefix="objc876-patches-") as directory:
        for index, (name, policy) in enumerate(PATCH_INPUTS.items()):
            patch = Path(directory) / f"{index:02d}.patch"
            patch.write_bytes(normalized_patch(decoded_input(patch_dir / name, policy["gzip"])))
            run(["git", "apply", "--check", str(patch)], cwd=source)
            run(["git", "apply", str(patch)], cwd=source)
    policy = (source / "runtime/objc-ptrauth.h").read_text(encoding="utf-8")
    required = (
        "__has_feature(ptrauth_calls) && __has_feature(ptrauth_restricted_intptr_qualifier)",
        "#if __has_feature(ptrauth_restricted_intptr_qualifier)",
        "__ptrauth_restricted_intptr",
    )
    if any(text not in policy for text in required):
        raise RuntimeError("restricted-integer ptrauth policy was not preserved")
    contract = (source / "runtime/compat/mach-o/dyld_priv.h").read_text(encoding="utf-8")
    for declaration in ("_dyld_objc_register_callbacks", "_dyld_objc_class_count"):
        if declaration not in contract:
            raise RuntimeError("dyld SPI compatibility declaration missing")
    for wrapper, dependency in COMPAT_INCLUDE_NEXT.items():
        text = (source / "runtime/compat" / wrapper).read_text(encoding="utf-8")
        includes = re.findall(r'^\s*#\s*include_next\s*<([^>]+)>', text, re.MULTILINE)
        if includes != [dependency]:
            raise RuntimeError("compatibility include_next mismatch: " + wrapper)


def normalize(argv, substitutions):
    result = []
    ordered = sorted(substitutions.items(), key=lambda item: len(item[0]), reverse=True)
    for argument in argv:
        value = str(argument)
        for actual, token in ordered:
            value = value.replace(actual, token)
        result.append(value)
    return result


def common_flags(source, build, public_root, sdk, integration_flags=()):
    return [
        "-target", TARGET, "-arch", "arm64e", "-mmacosx-version-min=" + MIN_OS,
        "-I" + str(build / "include"),
        "-I" + str(source / "runtime/compat"), "-I" + str(source / "runtime"),
        "-I" + str(public_root), "-isysroot", str(sdk),
        "-D__DARWIN_UNIX03", "-DDARLING", "-DDARWIN", "-DPLATFORM_MacOSX",
        "-DTARGET_OS_IPHONE=0", "-DTARGET_OS_MAC=1", "-DOBJC_IS_DEBUG_BUILD=0",
        "-DOBJC_NO_GC", "-DOS_OBJECT_USE_OBJC=0", "-D__STDC_NO_ATOMICS__",
        "-DDARLING_OBJC_VM_MAX_ADDRESS=0x00007ffffffffff8ULL", "-O2", "-DNDEBUG",
        "-g0", "-fPIC", "-fblocks", "-fobjc-legacy-dispatch", "-fvisibility=hidden",
        "-fstrict-aliasing", "-fno-delete-null-pointer-checks",
        "-Wno-nullability-completeness", "-Wno-deprecated-declarations",
        "-Wno-availability", "-Wno-invalid-offsetof", "-Wno-c++11-narrowing",
        "-Wno-unused-command-line-argument",
        *integration_flags,
    ]


def feature_probe(source, build, clangxx, flags):
    probe = build / "restricted-ptrauth.mm"
    probe.write_text(FEATURE_PROBE_SOURCE, encoding="utf-8")
    argv = [str(clangxx), *flags, "-std=gnu++14", "-fno-rtti", "-fno-exceptions",
            "-c", str(probe), "-o", str(build / "restricted-ptrauth.o")]
    run(argv)
    return argv


def compatibility_header_probes(build, clangxx, flags):
    commands = []
    for index, name in enumerate(HEADER_PROBE_NAMES):
        probe = build / f"compat-{index:02d}.mm"
        context = HEADER_PROBE_CONTEXT.get(name, {"probe_prelude": []})
        prelude = "".join(f"#include <{header}>\n"
                          for header in context["probe_prelude"])
        probe.write_text(prelude + f"#include <{name}>\n"
                         f"int auroraCompat{index}(void) {{ return 0; }}\n",
                         encoding="utf-8")
        argv = [str(clangxx), *flags, "-std=gnu++14", "-fno-rtti", "-fno-exceptions",
                "-fsyntax-only", str(probe)]
        run(argv)
        commands.append(argv)
    return commands


def audit_artifact_dir(artifact):
    entries = {path.name for path in artifact.iterdir()}
    if entries != ARTIFACT_FILES:
        raise RuntimeError("artifact allowlist mismatch: " + repr(sorted(entries)))
    for path in artifact.iterdir():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            raise RuntimeError("artifact entry is not a regular file: " + path.name)
    if (artifact / "libobjc.A.dylib").stat().st_size > 8 * 1024 * 1024:
        raise RuntimeError("libobjc artifact exceeds size bound")
    if any((artifact / name).stat().st_size > 1024 * 1024
           for name in ("build-argv.json", "provenance.json", "SHA256SUMS")):
        raise RuntimeError("metadata artifact exceeds size bound")


def make_provenance(input_hashes, compiler_version, compiler_hash, xcode_version,
                    sdk_version, object_count, required_export_count, dylib_bytes,
                    dylib_hash):
    return {
        "schema": "aurora_objc876_apple_clang_v1",
        "source": {"repository": "apple-oss-distributions/objc4",
                   "commit": OBJC_COMMIT, "tree": OBJC_TREE},
        "reviewed_inputs": input_hashes,
        "compiler": {"version": compiler_version, "sha256": compiler_hash},
        "xcode": list(xcode_version),
        "sdk": {"name": SDK_NAME, "version": sdk_version},
        "target": TARGET,
        "minimum_os": MIN_OS,
        "restricted_intptr_feature_probe": True,
        "production_object_count": object_count,
        "validation": {"architecture": "arm64e", "install_name": "/usr/lib/libobjc.A.dylib",
                       "required_export_count": required_export_count,
                       "missing_required_exports": 0},
        "libobjc": {"bytes": dylib_bytes, "sha256": dylib_hash},
    }


def build(source, patch_dir, public_root, build_dir, artifact, developer):
    verify_source(source)
    input_hashes = verify_inputs(patch_dir)
    public_headers = verify_public_headers(public_root)
    input_hashes["public_headers"] = public_headers
    integration_flags = full_dyld_priv_flags(public_headers)
    apply_patches(source, patch_dir)
    build_dir.mkdir(parents=True)
    artifact.mkdir(parents=True)
    prepared_public_root = materialize_public_headers(public_root, build_dir / "public-headers")
    xcode_version = tuple(output(["xcodebuild", "-version"]).splitlines())
    if xcode_version != XCODE_VERSION:
        raise RuntimeError("Xcode version/build mismatch")
    sdk_version = output(["xcrun", "--sdk", SDK_NAME, "--show-sdk-version"])
    if sdk_version != SDK_VERSION:
        raise RuntimeError("SDK version mismatch")
    sdk = Path(output(["xcrun", "--sdk", SDK_NAME, "--show-sdk-path"]))
    clang = Path(output(["xcrun", "--find", "clang"]))
    clangxx = Path(output(["xcrun", "--find", "clang++"]))
    if not sdk.is_dir() or not clang.is_file() or not clangxx.is_file():
        raise RuntimeError("pinned Apple compiler or SDK is unavailable")

    overlay = build_dir / "include/objc"
    overlay.mkdir(parents=True)
    for header in (source / "runtime").glob("*.h"):
        shutil.copy2(header, overlay / header.name)
    flags = common_flags(source, build_dir, prepared_public_root, sdk, integration_flags)
    commands = []
    commands.append(feature_probe(source, build_dir, clangxx, flags))
    commands.extend(compatibility_header_probes(build_dir, clangxx, flags))
    objects = []
    for index, name in enumerate(RUNTIME_SOURCES):
        source_path = source / "runtime" / name
        object_path = build_dir / (f"{index:02d}-" + name.replace("/", "_") + ".o")
        suffix = source_path.suffix
        if suffix == ".mm":
            argv = [str(clangxx), *flags, "-std=gnu++14", "-fno-rtti", "-fno-exceptions"]
        elif suffix == ".m":
            argv = [str(clang), *flags, "-x", "objective-c"]
        elif suffix == ".s":
            argv = [str(clang), *flags, "-x", "assembler-with-cpp"]
        else:
            raise RuntimeError("unhandled source suffix: " + suffix)
        argv += ["-c", str(source_path), "-o", str(object_path)]
        run(argv)
        commands.append(argv)
        objects.append(object_path)

    dylib = artifact / "libobjc.A.dylib"
    link = [
        str(clangxx), "-target", TARGET, "-arch", "arm64e",
        "-mmacosx-version-min=" + MIN_OS, "-isysroot", str(sdk), "-dynamiclib",
        "-stdlib=libc++", "-Wl,-install_name,/usr/lib/libobjc.A.dylib",
        "-Wl,-compatibility_version,1.0.0", "-Wl,-current_version,228.0.0",
        "-Wl,-undefined,dynamic_lookup", "-Wl,-not_for_dyld_shared_cache",
        "-Wl,-sectalign,__DATA,__objc_data,0x1000",
        "-Wl,-interposable_list," + str(source / "interposable.txt"),
        "-Wl,-rename_section,__DATA,__mod_init_func,__DATA,__objc_init_func",
        "-Wl,-unexported_symbols_list," + str(source / "unexported_symbols"),
        *map(str, objects), "-o", str(dylib),
    ]
    run(link)
    commands.append(link)

    if output(["lipo", "-archs", str(dylib)]) != "arm64e":
        raise RuntimeError("output is not a single arm64e slice")
    install_names = output(["otool", "-D", str(dylib)]).splitlines()
    if install_names[-1].strip() != "/usr/lib/libobjc.A.dylib":
        raise RuntimeError("unexpected dylib install name")
    load_commands = output(["otool", "-l", str(dylib)])
    if not re.search(r"\bminos\s+13\.0(?:\.0)?\b", load_commands):
        raise RuntimeError("output does not declare the macOS 13.0 minimum")
    exports = set(output(["nm", "-gU", str(dylib)]).split())
    required = {"_objc_msgSend", "_objc_getClass", "_objc_claimAutoreleasedReturnValue"}
    if not required.issubset(exports):
        raise RuntimeError("required modern objc exports are absent")

    substitutions = {
        str(source): "$SRC", str(build_dir): "$BUILD", str(sdk): "$SDK",
        str(artifact): "$ARTIFACT",
        str(prepared_public_root): "$PUBLIC_HEADERS",
        str(public_root): "$PUBLIC_HEADER_INPUTS",
        str(clangxx): "$CLANGXX", str(clang): "$CLANG", str(developer): "$DEVELOPER",
        str(patch_dir.parent.parent): "$REPO",
    }
    normalized = [normalize(command, substitutions) for command in commands]
    (artifact / "build-argv.json").write_text(
        json.dumps(normalized, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    compiler_version = output([str(clang), "--version"]).splitlines()[0]
    provenance = make_provenance(
        input_hashes, compiler_version, sha256(clang), xcode_version, sdk_version,
        len(objects), len(required), dylib.stat().st_size, sha256(dylib),
    )
    (artifact / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksum_names = ("libobjc.A.dylib", "build-argv.json", "provenance.json")
    (artifact / "SHA256SUMS").write_text(
        "".join(f"{sha256(artifact / name)}  {name}\n" for name in checksum_names),
        encoding="utf-8",
    )
    audit_artifact_dir(artifact)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path)
    parser.add_argument("--patch-dir", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--developer-dir", type=Path)
    parser.add_argument("--public-header-root", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    verify_inputs(args.patch_dir)
    if args.validate_only:
        if args.public_header_root is None:
            parser.error("validate-only requires public-header-root")
        verify_public_headers(args.public_header_root)
        if len(RUNTIME_SOURCES) != 33 or len(set(RUNTIME_SOURCES)) != 33:
            raise RuntimeError("production source graph is not exactly 33 unique objects")
        if ARTIFACT_FILES != {"libobjc.A.dylib", "build-argv.json", "provenance.json", "SHA256SUMS"}:
            raise RuntimeError("artifact allowlist changed")
        print("objc876 Apple-Clang proposal validation: PASS")
        return
    required = (args.source, args.build_dir, args.artifact, args.developer_dir,
                args.public_header_root)
    if any(value is None for value in required):
        parser.error("build mode requires source, build-dir, artifact, and developer-dir")
    if args.build_dir.exists() or args.artifact.exists():
        raise RuntimeError("build and artifact directories must not pre-exist")
    build(args.source, args.patch_dir, args.public_header_root, args.build_dir,
          args.artifact, args.developer_dir)


if __name__ == "__main__":
    main()
