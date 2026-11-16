#!/usr/bin/env python3
import importlib.util
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
SCRIPT = ROOT / ".github/scripts/build_objc876_apple.py"
SPEC = importlib.util.spec_from_file_location("build_objc876_apple", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
PINNED_RECIPE_HASHES = {
    ".github/scripts/build_objc876_apple.py":
        "418d5cb0ac1252f2ab732188e9566a2c7959381c2c80489257ac53b6a5ca4829",
    ".github/objc876/PATCHES.sha256":
        "eb47f4446014f5ad33c7dbd8ac5bf4251a35477339df9927669f29594ab2b931",
}


class AppleBuildPolicyTests(unittest.TestCase):
    def assert_pinned_recipe(self, root):
        for relative, expected in PINNED_RECIPE_HASHES.items():
            path = root / relative
            if not path.is_file() or path.is_symlink() or MODULE.sha256(path) != expected:
                raise RuntimeError("pinned recipe mismatch: " + relative)

    def compile_probe(self, source, headers):
        compiler = shutil.which("clang++")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "probe.mm").write_text(source)
            for name, contents in headers.items():
                (root / name).write_text(contents)
            return subprocess.run(
                [compiler, "-std=gnu++14", "-fsyntax-only", "-I" + str(root),
                 str(root / "probe.mm")],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )

    def test_graph_and_artifact_allowlist_are_bounded(self):
        self.assertEqual(len(MODULE.RUNTIME_SOURCES), 33)
        self.assertEqual(len(set(MODULE.RUNTIME_SOURCES)), 33)
        self.assertEqual(MODULE.ARTIFACT_FILES, {
            "libobjc.A.dylib", "build-argv.json", "provenance.json", "SHA256SUMS"
        })
        self.assert_pinned_recipe(ROOT)

    def test_pinned_recipe_rejects_missing_placeholder_and_wrong_hash(self):
        for case in ("missing", "placeholder", "wrong-hash"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for relative in PINNED_RECIPE_HASHES:
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ROOT / relative, target)
                target = root / ".github/scripts/build_objc876_apple.py"
                if case == "missing":
                    target.unlink()
                elif case == "placeholder":
                    target.write_bytes(b"")
                else:
                    target.write_bytes(target.read_bytes() + b"\n# altered\n")
                with self.assertRaises(RuntimeError):
                    self.assert_pinned_recipe(root)

    def test_verified_patch_hashes(self):
        observed = MODULE.verify_inputs(ROOT / ".github/objc876")
        self.assertEqual(
            observed["dyld_spi"]["content_sha256"],
            MODULE.DYLD_SPI_INPUT["content_sha256"],
        )
        self.assertEqual(len(observed["port_patches"]), 3)
        self.assertEqual(observed["header_probe_context"], {
            "sha256": MODULE.HEADER_PROBE_CONTEXT_SHA256,
            "header_count": 21, "production_source_count": 33,
        })
        headers = MODULE.verify_public_headers(ROOT / ".github/objc876/public-headers")
        self.assertEqual(set(headers), set(MODULE.ALL_HEADER_POLICIES))
        self.assertEqual(len(MODULE.PUBLIC_HEADERS), 18)
        self.assertEqual(set(MODULE.LOCAL_COMPAT_HEADERS),
                         {"CrashReporterClient.h", "os/feature_private.h", "sandbox/private.h"})
        for name in MODULE.LOCAL_COMPAT_HEADERS:
            self.assertEqual(headers[name]["provenance_class"], "darling_low_level_compat")
            self.assertEqual(MODULE.LOCAL_COMPAT_HEADERS[name]["license"], "GPL-3.0-only")
            self.assertEqual(MODULE.LOCAL_COMPAT_HEADERS[name]["license_source"],
                             "repository-root LICENSE at pinned commit")
            self.assertEqual(MODULE.LOCAL_COMPAT_HEADERS[name]["license_status"],
                             "governing repository license; file has no standalone license notice")
        for name in MODULE.PUBLIC_HEADERS:
            self.assertEqual(headers[name]["provenance_class"], "official_apple_oss")
        for name, (license_name, asserted) in MODULE.OFFICIAL_LICENSE_POLICY.items():
            self.assertEqual(MODULE.PUBLIC_HEADERS[name]["license"], license_name)
            self.assertIs(MODULE.PUBLIC_HEADERS[name]["license_asserted"], asserted)
        self.assertNotIn("APSL", MODULE.PUBLIC_HEADERS["Block_private.h"]["license"])
        self.assertIs(MODULE.PUBLIC_HEADERS["Block_private.h"]["license_asserted"], False)
        dyld = headers["mach-o/dyld_priv.h"]
        self.assertEqual(dyld["sha256"],
                         "82eb5bcf0dd6f8fa1305c69110b2e7c333b74375433d8216d7a29452a7374ac8")
        self.assertEqual(dyld["stored_sha256"],
                         "c26fbc499831bdf43b5158462438bf83a138d6baf694b7e14e87e3966d3ac502")
        self.assertEqual(dyld["materialization"], {
            "declarations": list(MODULE.DYLD_BRIDGEOS_DECLARATIONS),
            "normalized_sha256":
                "9f8ce4c1e3e1ab2d34d3d3af3a3d7c77003455a76e69c16940b7e57b06d0c615",
            "platform_scope": "macos-only", "removal_count": 8,
            "rule": "remove-final-bridgeos-3.0-from-four-platform-api-available",
        })
        reason = headers["sys/reason.h"]
        self.assertEqual(reason["sha256"],
                         "782540658b7d4af1fb7278de7868874e374db6c35af5be9756a19ee4b6983cb3")
        self.assertEqual(reason["stored_sha256"], reason["sha256"])

    def test_full_dyld_macro_requires_exact_verified_header(self):
        headers = MODULE.verify_public_headers(ROOT / ".github/objc876/public-headers")
        self.assertEqual(MODULE.full_dyld_priv_flags(headers),
                         [MODULE.FULL_DYLD_PRIV_DEFINE])
        with self.assertRaises(RuntimeError):
            MODULE.full_dyld_priv_flags({})
        for field in ("sha256", "stored_sha256"):
            bad = json.loads(json.dumps(headers))
            bad["mach-o/dyld_priv.h"][field] = "0" * 64
            with self.assertRaises(RuntimeError):
                MODULE.full_dyld_priv_flags(bad)

    def test_artifact_provenance_retains_content_and_stored_hashes(self):
        headers = MODULE.verify_public_headers(ROOT / ".github/objc876/public-headers")
        record = MODULE.make_provenance(
            {"public_headers": headers}, "Apple clang test", "c" * 64,
            MODULE.XCODE_VERSION, MODULE.SDK_VERSION, 33, 3, 1234, "d" * 64,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "provenance.json"
            path.write_text(json.dumps(record, sort_keys=True) + "\n")
            generated = json.loads(path.read_text())
        dyld = generated["reviewed_inputs"]["public_headers"]["mach-o/dyld_priv.h"]
        self.assertEqual(dyld["sha256"],
                         "82eb5bcf0dd6f8fa1305c69110b2e7c333b74375433d8216d7a29452a7374ac8")
        self.assertEqual(dyld["stored_sha256"],
                         "c26fbc499831bdf43b5158462438bf83a138d6baf694b7e14e87e3966d3ac502")
        reason = generated["reviewed_inputs"]["public_headers"]["sys/reason.h"]
        self.assertEqual(reason["sha256"], reason["stored_sha256"])

    def public_header_fixture(self, root):
        public = root / "public-headers"
        for policy in MODULE.ALL_HEADER_POLICIES.values():
            target = public / policy["stored_path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / ".github/objc876/public-headers" / policy["stored_path"],
                         target)
        shutil.copy2(ROOT / ".github/objc876/PUBLIC_HEADERS.json",
                     root / "PUBLIC_HEADERS.json")
        shutil.copy2(ROOT / ".github/objc876/LOCAL_COMPAT_HEADERS.json",
                     root / "LOCAL_COMPAT_HEADERS.json")
        return public

    def test_public_header_tree_rejects_all_unexpected_entry_types(self):
        cases = ("dangling", "symlink", "fifo", "extra-directory", "extra-file",
                 "missing", "corrupt", "corrupt-gzip", "provenance")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                public = self.public_header_fixture(root)
                if case == "dangling":
                    (public / "dangling").symlink_to(public / "absent")
                elif case == "symlink":
                    (public / "linked").symlink_to(public / "sys/reason.h")
                elif case == "fifo":
                    os.mkfifo(public / "pipe")
                elif case == "extra-directory":
                    (public / "extra").mkdir()
                elif case == "extra-file":
                    (public / "extra.h").write_text("extra\n")
                elif case == "missing":
                    (public / "sys/reason.h").unlink()
                elif case == "corrupt":
                    (public / "sys/reason.h").write_text("corrupt\n")
                elif case == "corrupt-gzip":
                    (public / "mach-o/dyld_priv.h.gz").write_bytes(b"not gzip")
                else:
                    (root / "PUBLIC_HEADERS.json").write_text("{}\n")
                with self.assertRaises(RuntimeError):
                    MODULE.verify_public_headers(public)

    def test_public_header_materialization_is_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = self.public_header_fixture(root)
            output = MODULE.materialize_public_headers(inputs, root / "prepared")
            entries = MODULE.enumerate_directory(output)
            logical_files = set(MODULE.ALL_HEADER_POLICIES)
            logical_dirs = {str(parent) for name in logical_files
                            for parent in Path(name).parents if str(parent) != "."}
            self.assertEqual(entries, {"files": logical_files, "directories": logical_dirs})
            for name, policy in MODULE.ALL_HEADER_POLICIES.items():
                expected = policy.get("materialization", {}).get(
                    "normalized_sha256", policy["sha256"]
                )
                self.assertEqual(MODULE.sha256(output / name), expected)

    def test_bridgeos_normalization_is_exact_and_hash_pinned(self):
        policy = MODULE.PUBLIC_HEADERS["mach-o/dyld_priv.h"]
        stored = ROOT / ".github/objc876/public-headers" / policy["stored_path"]
        source = gzip.decompress(stored.read_bytes())
        normalized = MODULE.normalize_dyld_priv_for_macos(source)
        needle = b", bridgeos(3.0)"
        self.assertEqual(source.count(needle), 8)
        self.assertEqual(normalized.count(needle), 0)
        self.assertEqual(normalized, source.replace(needle, b""))
        self.assertEqual(len(source) - len(normalized), 8 * len(needle))
        self.assertEqual(hashlib.sha256(normalized).hexdigest(),
                         policy["materialization"]["normalized_sha256"])

    def test_bridgeos_normalization_rejects_count_context_platform_and_nesting(self):
        policy = MODULE.PUBLIC_HEADERS["mach-o/dyld_priv.h"]
        source = gzip.decompress(
            (ROOT / ".github/objc876/public-headers" / policy["stored_path"]).read_bytes()
        )
        cases = {
            "count": source.replace(b", bridgeos(3.0)", b"", 1),
            "context": source.replace(b"dyld_get_active_platform", b"dyld_other_platform", 1),
            "platform": source.replace(b"ios(12.0)", b"ios(13.0)", 1),
            "nesting": source.replace(b"macos(10.14)", b"macos((10.14)", 1),
        }
        for name, malformed in cases.items():
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                MODULE.normalize_dyld_priv_for_macos(malformed)

    def test_public_sdk_shape_reproduces_eight_errors_then_normalized_passes(self):
        compiler = shutil.which("clang++")
        self.assertIsNotNone(compiler)
        policy = MODULE.PUBLIC_HEADERS["mach-o/dyld_priv.h"]
        source = gzip.decompress(
            (ROOT / ".github/objc876/public-headers" / policy["stored_path"]).read_bytes()
        )
        normalized = MODULE.normalize_dyld_priv_for_macos(source)
        needle = b", bridgeos(3.0)"
        original_lines = [line for line in source.decode().splitlines() if needle.decode() in line]
        normalized_lines = [line.replace(needle.decode(), "") for line in original_lines]
        preamble = (
            "#define __API_AVAILABLE(a,b,c,d)\n"
            "typedef unsigned int uint32_t; typedef uint32_t dyld_platform_t;\n"
            "typedef struct { dyld_platform_t platform; uint32_t version; } dyld_build_version_t;\n"
            "struct mach_header;\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_path = root / "original.mm"
            normalized_path = root / "normalized.mm"
            original_path.write_text(preamble + "\n".join(original_lines) + "\n")
            normalized_path.write_text(preamble + "\n".join(normalized_lines) + "\n")
            original = subprocess.run(
                [compiler, "-std=gnu++14", "-fblocks", "-fsyntax-only", str(original_path)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            fixed = subprocess.run(
                [compiler, "-std=gnu++14", "-fblocks", "-fsyntax-only", str(normalized_path)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
        self.assertNotEqual(original.returncode, 0)
        self.assertGreaterEqual(original.stdout.count("too many arguments"), 8)
        self.assertEqual(fixed.returncode, 0, fixed.stdout)
        self.assertEqual(normalized, source.replace(needle, b""))

    def test_all_private_availability_normalizations_are_exact(self):
        root = ROOT / ".github/objc876/public-headers"
        for name in ("gethostuuid.h", "os/lock_private.h", "os/variant_private.h",
                     "pthread/pthread.h"):
            with self.subTest(name=name):
                policy = MODULE.PUBLIC_HEADERS[name]
                stored = (root / policy["stored_path"]).read_bytes()
                source = gzip.decompress(stored) if policy["stored_compression"] == "gzip" else stored
                normalized = MODULE.normalize_private_availability_for_macos(name, source)
                expected = source.decode()
                removed = 0
                for rule in policy["materialization"]["private_platform_removals"]:
                    self.assertEqual(expected.count(rule["needle"]), rule["count"])
                    removed += rule["count"] * (len(rule["needle"]) - len(rule["replacement"]))
                    expected = expected.replace(rule["needle"], rule["replacement"])
                self.assertEqual(normalized, expected.encode())
                self.assertEqual(len(source) - len(normalized), removed)
                self.assertEqual(hashlib.sha256(normalized).hexdigest(),
                                 policy["materialization"]["normalized_sha256"])

    def test_private_availability_malformed_inputs_fail_closed(self):
        root = ROOT / ".github/objc876/public-headers"
        for name in ("gethostuuid.h", "os/lock_private.h", "os/variant_private.h",
                     "pthread/pthread.h"):
            policy = MODULE.PUBLIC_HEADERS[name]
            stored = (root / policy["stored_path"]).read_bytes()
            source = gzip.decompress(stored) if policy["stored_compression"] == "gzip" else stored
            rule = policy["materialization"]["private_platform_removals"][0]
            cases = {
                "count": source.replace(rule["needle"].encode(), b"", 1),
                "context": source.replace(rule["contexts"][0].encode(), b"changed_context", 1),
                "platform": source.replace(rule["needle"].encode(), b", xros(1.0)", 1),
                "unexpected": source + b"\nbridgeos(99.0)\n",
            }
            for case, malformed in cases.items():
                with self.subTest(name=name, case=case), self.assertRaises(RuntimeError):
                    MODULE.normalize_private_availability_for_macos(name, malformed)

    def test_private_availability_public_sdk_errors_then_normalized_passes(self):
        compiler = shutil.which("clang++")
        self.assertIsNotNone(compiler)
        original = (
            "#define __SPI_AVAILABLE(a,b,c)\n#define __API_AVAILABLE(a,b,c,d)\n"
            "#define API_AVAILABLE(a,b,c,d)\n#define API_UNAVAILABLE(a,b,c)\n"
            "#define __API_UNAVAILABLE(a,b,c,d)\n"
            "__SPI_AVAILABLE(ios(2.0), tvos(9.0), watchos(1.0), bridgeos(2.0))\n"
            "__API_AVAILABLE(macos(10.15), ios(13.0), tvos(13.0), watchos(6.0), bridgeos(4.0))\n"
            "API_AVAILABLE(macosx(10.15), ios(13.0), tvos(13.0), watchos(6.0), bridgeos(4.0))\n"
            "API_UNAVAILABLE(ios, tvos, watchos, bridgeos)\n"
            "__API_UNAVAILABLE(ios, tvos, watchos, bridgeos, driverkit)\nint value;\n"
        )
        normalized = (original.replace(", bridgeos(2.0)", "")
                      .replace(", bridgeos(4.0)", "")
                      .replace(", bridgeos)", ")")
                      .replace(", bridgeos, driverkit", ", driverkit"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_path = root / "original.mm"; original_path.write_text(original)
            normalized_path = root / "normalized.mm"; normalized_path.write_text(normalized)
            bad = subprocess.run([compiler, "-fsyntax-only", str(original_path)], text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            good = subprocess.run([compiler, "-fsyntax-only", str(normalized_path)], text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertNotEqual(bad.returncode, 0)
        self.assertGreaterEqual(bad.stdout.count("too many arguments"), 5)
        self.assertEqual(good.returncode, 0, good.stdout)

    def test_public_header_root_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = self.public_header_fixture(root / "real")
            linked = root / "linked-root"
            linked.symlink_to(inputs, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                MODULE.verify_public_headers(linked)
            dangling = root / "dangling-root"
            dangling.symlink_to(root / "absent", target_is_directory=True)
            with self.assertRaises((RuntimeError, FileNotFoundError)):
                MODULE.verify_public_headers(dangling)

    def test_local_compat_provenance_commit_and_exact_allowlist_fail_closed(self):
        cases = ("commit", "add", "remove", "fourth", "missing-semantics",
                 "changed-semantics")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                public = self.public_header_fixture(root)
                metadata = root / "LOCAL_COMPAT_HEADERS.json"
                document = json.loads(metadata.read_text())
                if case == "commit":
                    document["commit"] = "0" * 40
                elif case == "add":
                    document["headers"]["unexpected.h"] = {"semantics": "unexpected"}
                elif case == "remove":
                    document["headers"].pop("CrashReporterClient.h")
                elif case == "fourth":
                    document["headers"]["fourth.h"] = dict(
                        document["headers"]["CrashReporterClient.h"]
                    )
                elif case == "missing-semantics":
                    document["headers"]["CrashReporterClient.h"].pop("semantics")
                else:
                    document["headers"]["CrashReporterClient.h"]["semantics"] = "changed"
                metadata.write_text(json.dumps(document, sort_keys=True) + "\n")
                original_hash = MODULE.LOCAL_COMPAT_PROVENANCE_SHA256
                MODULE.LOCAL_COMPAT_PROVENANCE_SHA256 = MODULE.sha256(metadata)
                try:
                    with self.assertRaises(RuntimeError):
                        MODULE.verify_public_headers(public)
                finally:
                    MODULE.LOCAL_COMPAT_PROVENANCE_SHA256 = original_hash

    def test_workflow_checksum_command_from_repository_root(self):
        result = subprocess.run(
            ["shasum", "-a", "256", "-c", ".github/objc876/PATCHES.sha256"],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_runner_inventory_checksum_command_from_repository_root(self):
        result = subprocess.run(
            ["shasum", "-a", "256", "-c", ".github/objc876/RUNNER_IMAGE.sha256"],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_normalized_applied_patch_text_has_no_whitespace_errors(self):
        for name, policy in MODULE.PATCH_INPUTS.items():
            source = MODULE.decoded_input(ROOT / ".github/objc876" / name, policy["gzip"])
            normalized = MODULE.normalized_patch(source)
            for line in normalized.splitlines():
                if line.startswith(b"+") and not line.startswith(b"+++"):
                    self.assertEqual(line, line.rstrip(b" \t"), name)
                    self.assertIsNone(re.match(br"^\+ +\t", line), name)

    def test_old_probe_reproduces_missing_private_declaration(self):
        source = MODULE.OLD_FEATURE_PROBE_SOURCE.replace(
            "__has_feature(ptrauth_calls)", "1"
        ).replace("__has_feature(ptrauth_restricted_intptr_qualifier)", "1")
        header = (
            "static inline void *_method_auth(Method mSigned) { return mSigned; }\n"
            "#define ptrauth_class_rx_enforce\n"
            "#define ptrauth_trampoline_textSegment\n"
        )
        result = self.compile_probe(source, {"objc-ptrauth.h": header})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Method", result.stdout)

    def test_new_probe_is_self_contained_when_features_are_available(self):
        source = MODULE.FEATURE_PROBE_SOURCE.replace(
            "__has_feature(ptrauth_calls)", "1"
        ).replace("__has_feature(ptrauth_restricted_intptr_qualifier)", "1")
        header = (
            "#define ptrauth_key_process_dependent_data 2\n"
            "#define ptrauth_string_discriminator(value) 0\n"
            "#define __ptrauth_restricted_intptr(key, address, discriminator)\n"
        )
        result = self.compile_probe(source, {"ptrauth.h": header})
        self.assertEqual(result.returncode, 0, result.stdout)
        for private_name in ("objc-ptrauth.h", "Method", "METHOD_SIGNING_DISCRIMINATOR", "method_t"):
            self.assertNotIn(private_name, MODULE.FEATURE_PROBE_SOURCE)

    def test_new_probe_fails_closed_when_restricted_feature_is_absent(self):
        source = MODULE.FEATURE_PROBE_SOURCE.replace(
            "__has_feature(ptrauth_calls)", "1"
        )
        header = (
            "#define ptrauth_key_process_dependent_data 2\n"
            "#define ptrauth_string_discriminator(value) 0\n"
            "#define __ptrauth_restricted_intptr(key, address, discriminator)\n"
        )
        result = self.compile_probe(source, {"ptrauth.h": header})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("restricted_intptr_required", result.stdout)

    def test_post_patch_include_order_and_resolution(self):
        patch = MODULE.decoded_input(
            ROOT / ".github/objc876/0001-objc4-876-darling-source-compat.patch.gz", True
        ).decode("utf-8")
        for name in MODULE.PATCH_COMPAT_HEADERS:
            self.assertIn("runtime/compat/" + name, patch)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            build = root / "build"
            public = root / "public"
            sdk = root / "sdk"
            for name in MODULE.PATCH_COMPAT_HEADERS:
                path = source / "runtime/compat" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("compat\n")
            (source / "runtime").mkdir(parents=True, exist_ok=True)
            (build / "include/objc").mkdir(parents=True, exist_ok=True)
            (public / "sys").mkdir(parents=True, exist_ok=True)
            (public / "sys/reason.h").write_text("reason\n")
            (public / "mach-o").mkdir(parents=True)
            (public / "mach-o/dyld_priv.h").write_text("dyld private\n")
            for name in ("TargetConditionals.h", "mach-o/dyld.h", "ptrauth.h", "stdint.h"):
                path = sdk / "usr/include" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("sdk\n")
            roots = MODULE.include_search_roots(source, build, public, sdk)
            self.assertEqual(roots, (build / "include", source / "runtime/compat",
                                     source / "runtime", public, sdk / "usr/include"))
            self.assertEqual(MODULE.resolve_header("sys/reason.h", roots),
                             public / "sys/reason.h")
            for name in MODULE.PATCH_COMPAT_HEADERS:
                self.assertEqual(MODULE.resolve_header(name, roots),
                                 source / "runtime/compat" / name)
            for name in ("TargetConditionals.h", "mach-o/dyld.h", "ptrauth.h"):
                self.assertEqual(
                    MODULE.resolve_header(name, roots, after=source / "runtime/compat"),
                    sdk / "usr/include" / name,
                )
            self.assertEqual(
                MODULE.resolve_header("mach-o/dyld_priv.h", roots,
                                      after=source / "runtime/compat"),
                public / "mach-o/dyld_priv.h",
            )
            self.assertEqual(MODULE.resolve_header("stdint.h", roots), sdk / "usr/include/stdint.h")
            flags = MODULE.common_flags(source, build, public, sdk)
            include_flags = [flag for flag in flags if flag.startswith("-I")]
            self.assertEqual(include_flags[:4], ["-I" + str(path) for path in roots[:4]])
            self.assertNotIn(MODULE.FULL_DYLD_PRIV_DEFINE, flags)
            full_flags = MODULE.common_flags(
                source, build, public, sdk,
                MODULE.full_dyld_priv_flags(
                    MODULE.verify_public_headers(ROOT / ".github/objc876/public-headers")
                ),
            )
            self.assertIn(MODULE.FULL_DYLD_PRIV_DEFINE, full_flags)

    def added_compat_header(self, name):
        patch = MODULE.decoded_input(
            ROOT / ".github/objc876/0001-objc4-876-darling-source-compat.patch.gz", True
        ).decode("utf-8")
        marker = f"diff --git i/runtime/compat/{name} w/runtime/compat/{name}\n"
        segment = patch.split(marker, 1)[1].split("\ndiff --git ", 1)[0]
        body = []
        in_hunk = False
        for line in segment.splitlines():
            if line.startswith("@@"):
                in_hunk = True
            elif in_hunk and line.startswith("+") and not line.startswith("+++"):
                body.append(line[1:])
        return "\n".join(body) + "\n"

    def write_final_compat_headers(self, root):
        for name in MODULE.PATCH_COMPAT_HEADERS:
            path = root / "runtime/compat" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.added_compat_header(name))
        subprocess.run(
            ["git", "apply", str(ROOT / ".github/objc876/0003-objc4-876-full-dyld-priv.patch")],
            cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        return root / "runtime/compat"

    def compile_dyld_wrapper(self, full_header, use_macro=None):
        compiler = shutil.which("clang++")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compat = self.write_final_compat_headers(root)
            public = root / "public"
            sdk = root / "sdk"
            (public / "mach-o").mkdir(parents=True)
            if full_header:
                (public / "mach-o/dyld_priv.h").write_text(
                    "#include <stdint.h>\nstruct mach_header;\n"
                    "struct _dyld_objc_callbacks { uintptr_t version; };\n"
                    "struct _dyld_objc_callbacks_v1 { uintptr_t version; };\n"
                )
            else:
                (public / "mach-o/dyld_priv.h").write_text(
                    "#include <stdint.h>\nstruct mach_header;\n"
                )
            (sdk / "stdint.h").parent.mkdir(parents=True, exist_ok=True)
            (sdk / "stdint.h").write_text(
                "typedef unsigned int uint32_t; typedef unsigned long uintptr_t;\n"
            )
            source = root / "probe.mm"
            source.write_text(
                "#include <mach-o/dyld_priv.h>\n"
                "static struct _dyld_objc_callbacks_v1 callbackTable;\n"
                "int main() { return (int)callbackTable.version; }\n"
            )
            argv = [compiler, "-std=gnu++14", "-fsyntax-only", "-nostdinc",
                    "-I" + str(compat), "-I" + str(public), "-I" + str(sdk)]
            if use_macro is None:
                use_macro = full_header
            if use_macro:
                argv.append(MODULE.FULL_DYLD_PRIV_DEFINE)
            argv.append(str(source))
            return subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)

    def test_full_dyld_header_has_no_callback_redefinition(self):
        result = self.compile_dyld_wrapper(True)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_full_dyld_header_without_macro_fails_closed(self):
        result = self.compile_dyld_wrapper(True, use_macro=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("redefinition", result.stdout)

    def test_fallback_dyld_header_still_defines_callbacks(self):
        result = self.compile_dyld_wrapper(False)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_all_compatibility_tus_compile_with_private_bases_outside_sdk(self):
        compiler = shutil.which("clang++")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compat = root / "compat"
            public = root / "public"
            sdk = root / "sdk"
            compat = self.write_final_compat_headers(root)
            (public / "sys").mkdir(parents=True)
            shutil.copy2(ROOT / ".github/objc876/public-headers/sys/reason.h",
                         public / "sys/reason.h")
            (public / "mach-o").mkdir(parents=True)
            (public / "mach-o/dyld_priv.h").write_text(
                "#include <stdint.h>\nstruct mach_header;\n"
                "struct _dyld_objc_callbacks { uintptr_t version; };\n"
                "struct _dyld_objc_callbacks_v1 { uintptr_t version; };\n"
            )
            for name in MODULE.ALL_HEADER_POLICIES:
                if name in ("mach-o/dyld_priv.h", "sys/reason.h"):
                    continue
                path = public / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n")
            sdk_headers = {
                "stdint.h": ("#define __BEGIN_DECLS extern \"C\" {\n#define __END_DECLS }\n"
                              "typedef unsigned int uint32_t; typedef unsigned long uintptr_t; "
                              "typedef unsigned long long uint64_t;\n#define UINT32_MAX 0xffffffffU\n"),
                "TargetConditionals.h": "#define TARGET_OS_EXCLAVEKIT 0\n",
                "Availability.h": "\n",
                "mach-o/dyld.h": "#include <stdint.h>\nstruct mach_header;\n",
                "ptrauth.h": ("#include <stdint.h>\n#define ptrauth_key_process_independent_data 2\n"
                              "#define ptrauth_key_process_dependent_data 3\n"),
                "pthread.h": "typedef void *pthread_t; typedef struct { int value; } pthread_attr_t;\n",
            }
            for name, contents in sdk_headers.items():
                path = sdk / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            for index, name in enumerate(MODULE.HEADER_PROBE_NAMES):
                source = root / f"probe-{index}.mm"
                context = MODULE.HEADER_PROBE_CONTEXT.get(name, {"probe_prelude": []})
                prelude = "".join(f"#include <{header}>\n"
                                  for header in context["probe_prelude"])
                source.write_text(prelude + f"#include <{name}>\n"
                                  f"int probe{index}(void) {{ return 0; }}\n")
                result = subprocess.run(
                    [compiler, "-std=gnu++14", "-fsyntax-only", "-nostdinc",
                     MODULE.FULL_DYLD_PRIV_DEFINE, "-I" + str(compat),
                     "-I" + str(public), "-I" + str(sdk), str(source)],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                )
                self.assertEqual(result.returncode, 0, name + "\n" + result.stdout)

    def test_production_compat_probes_include_prerequisites_in_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            captured = []
            original_run = MODULE.run
            try:
                MODULE.run = lambda argv, cwd=None: captured.append(argv)
                commands = MODULE.compatibility_header_probes(
                    root, Path("/tool/clang++"), ["-target", MODULE.TARGET]
                )
            finally:
                MODULE.run = original_run
            self.assertEqual(commands, captured)
            self.assertEqual(len(commands), len(MODULE.HEADER_PROBE_NAMES))
            for index, name in enumerate(MODULE.HEADER_PROBE_NAMES):
                lines = (root / f"compat-{index:02d}.mm").read_text().splitlines()
                context = MODULE.HEADER_PROBE_CONTEXT.get(name, {"probe_prelude": []})
                expected = [f"#include <{header}>" for header in context["probe_prelude"]]
                self.assertEqual(lines[:len(expected)], expected)
                self.assertEqual(lines[len(expected)], f"#include <{name}>")

    def test_pthread_probe_prelude_missing_wrong_or_reordered_fails(self):
        compiler = shutil.which("clang++")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pthread.h").write_text(
                "typedef void *pthread_t; typedef struct { int value; } pthread_attr_t;\n"
            )
            (root / "probe_header.h").write_text(
                "pthread_t thread; pthread_attr_t attribute;\n"
            )
            cases = {
                "correct": "#include <pthread.h>\n#include <probe_header.h>\n",
                "missing": "#include <probe_header.h>\n",
                "wrong": "#include <stdint.h>\n#include <probe_header.h>\n",
                "reordered": "#include <probe_header.h>\n#include <pthread.h>\n",
            }
            for name, source in cases.items():
                path = root / (name + ".mm")
                path.write_text(source)
                result = subprocess.run(
                    [compiler, "-std=gnu++14", "-fsyntax-only", "-I" + str(root), str(path)],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                )
                if name == "correct":
                    self.assertEqual(result.returncode, 0, result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0, name)

    def test_naked_probe_context_is_explicit_and_self_contained(self):
        self.assertEqual(MODULE.HEADER_PROBE_CONTEXT["CrashReporterClient.h"]["probe_prelude"], [])
        result = self.compile_probe("#include <CrashReporterClient.h>\nint main(){return 0;}\n",
                                    {"CrashReporterClient.h":
                                     (ROOT / ".github/objc876/public-headers/CrashReporterClient.h").read_text()})
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_probe_context_manifest_mutations_fail_closed(self):
        path = ROOT / ".github/objc876/HEADER_PROBE_CONTEXT.json"
        original_hash = MODULE.HEADER_PROBE_CONTEXT_SHA256
        for case in ("missing", "wrong", "order"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                patch_dir = Path(directory)
                for name in ("0001-objc4-876-darling-source-compat.patch.gz",
                             "0002-objc4-876-darling-cmake-graph.patch",
                             "0003-objc4-876-full-dyld-priv.patch",
                             "objc4-876-dyld-spi.patch.gz", "OBJC876_HEADERS.json"):
                    shutil.copy2(ROOT / ".github/objc876" / name, patch_dir / name)
                document = json.loads(path.read_text())
                if case == "missing":
                    document["headers"].pop("System/pthread_machdep.h")
                elif case == "wrong":
                    document["headers"]["System/pthread_machdep.h"]["probe_prelude"] = ["stdint.h"]
                else:
                    document["headers"]["System/pthread_machdep.h"]["probe_prelude"] = ["pthread.h", "stdint.h"]
                target = patch_dir / "HEADER_PROBE_CONTEXT.json"
                target.write_text(json.dumps(document, sort_keys=True) + "\n")
                MODULE.HEADER_PROBE_CONTEXT_SHA256 = MODULE.sha256(target)
                try:
                    with self.assertRaises(RuntimeError):
                        MODULE.verify_inputs(patch_dir)
                finally:
                    MODULE.HEADER_PROBE_CONTEXT_SHA256 = original_hash

    def test_public_reason_header_required_by_exact_compile_shape(self):
        compiler = shutil.which("clang++")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdk = root / "sdk"
            sdk.mkdir()
            (sdk / "stdint.h").write_text(
                "#define __BEGIN_DECLS extern \"C\" {\n#define __END_DECLS }\n"
                "typedef unsigned int uint32_t; typedef unsigned long long uint64_t;\n"
                "#define UINT32_MAX 0xffffffffU\n"
            )
            source = root / "reason.mm"
            source.write_text("#include <sys/reason.h>\nint main() { return OS_REASON_OBJC != 8; }\n")
            base = [compiler, "-std=gnu++14", "-fsyntax-only", "-nostdinc", "-I" + str(sdk)]
            missing = subprocess.run([*base, str(source)], text=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("sys/reason.h", missing.stdout)
            present = subprocess.run(
                [compiler, "-std=gnu++14", "-fsyntax-only", "-nostdinc",
                 "-I" + str(ROOT / ".github/objc876/public-headers"),
                 "-I" + str(sdk), str(source)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            self.assertEqual(present.returncode, 0, present.stdout)

    def test_normalization_removes_host_paths(self):
        result = MODULE.normalize(
            ["/private/sdk/usr/bin/clang", "-I/private/source/runtime"],
            {"/private/sdk": "$SDK", "/private/source": "$SRC"},
        )
        self.assertEqual(result, ["$SDK/usr/bin/clang", "-I$SRC/runtime"])

    def test_artifact_audit_rejects_extra_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in MODULE.ARTIFACT_FILES:
                (root / name).write_bytes(b"x")
            MODULE.audit_artifact_dir(root)
            (root / "compiler").write_bytes(b"x")
            with self.assertRaises(RuntimeError):
                MODULE.audit_artifact_dir(root)
            (root / "compiler").unlink()
            (root / "provenance.json").unlink()
            (root / "provenance.json").symlink_to(root / "SHA256SUMS")
            with self.assertRaises(RuntimeError):
                MODULE.audit_artifact_dir(root)

    def test_workflow_is_manual_and_uploads_only_artifact_directory(self):
        workflow = (ROOT / ".github/workflows/objc876-apple-clang.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotRegex(workflow, re.compile(r"(?m)^\s*(push|pull_request|schedule):"))
        self.assertIn("path: ${{ runner.temp }}/objc876-artifact/", workflow)
        self.assertEqual(workflow.count("uses: actions/upload-artifact@"), 1)
        self.assertNotIn("if: always()", workflow)
        self.assertIn("Xcode 16.4\\nBuild version 16F6", workflow)
        self.assertIn("AURORA_SDK: macosx15.5", workflow)
        self.assertIn("runs-on: macos-15-intel", workflow)
        self.assertNotRegex(workflow, re.compile(r"(?m)^\s*runs-on: macos-15\s*$"))
        original = workflow.replace("runs-on: macos-15-intel", "runs-on: macos-15")
        self.assertEqual(
            hashlib.sha256(original.encode()).hexdigest(),
            "9b6d9a8293474fb10ff39b5fdc31b25547266ceb6227eb8205497cdcfc150cd0",
        )

    def test_official_intel_runner_inventory_is_pinned(self):
        inventory = json.loads((ROOT / ".github/objc876/RUNNER_IMAGE.json").read_text())
        self.assertEqual(inventory["repository"],
                         "https://github.com/actions/runner-images.git")
        self.assertEqual(inventory["commit"],
                         "67421cc1650a2ab8eac05d4674a787d25dc51627")
        self.assertEqual(inventory["assertions"], {
            "architecture": "x64", "label": "macos-15-intel",
            "sdk_name": "macosx15.5", "sdk_version": "15.5",
            "xcode_build": "16F6", "xcode_version": "16.4",
        })
        for name, policy in inventory["files"].items():
            stored = ROOT / ".github/objc876" / policy["stored_path"]
            self.assertEqual(MODULE.sha256(stored), policy["stored_sha256"])
            decoded = gzip.decompress(stored.read_bytes())
            self.assertEqual(hashlib.sha256(decoded).hexdigest(), policy["sha256"])
            text = decoded.decode()
            if name == "README.md":
                self.assertRegex(text, re.compile(
                    r"(?m)^\| macOS 15.*\| x64 \| `macos-15-large`, or `macos-15-intel` \|"))
            else:
                self.assertIn("| 16.4 (default) | 16F6", text)
                self.assertIn("| macOS 15.5", text)
                self.assertIn("| macosx15.5", text)

    def test_arm64e_outputs_are_compile_link_or_metadata_only(self):
        helper = (ROOT / ".github/scripts/build_objc876_apple.py").read_text()
        workflow = (ROOT / ".github/workflows/objc876-apple-clang.yml").read_text()
        for forbidden in ("subprocess.Popen", "os.exec", "os.system", "chmod +x",
                          "codesign", "./libobjc.A.dylib"):
            self.assertNotIn(forbidden, helper + workflow)
        self.assertIn('"-target", TARGET', helper)
        self.assertIn('"-fsyntax-only"', helper)
        self.assertIn('"-dynamiclib"', helper)
        self.assertIn('output(["lipo", "-archs", str(dylib)])', helper)
        self.assertIn('output(["otool", "-D", str(dylib)])', helper)
        self.assertIn('output(["nm", "-gU", str(dylib)])', helper)

    def proposal_expected_files(self):
        fixed_objc_files = {
            ".github/objc876/0001-objc4-876-darling-source-compat.patch.gz",
            ".github/objc876/0002-objc4-876-darling-cmake-graph.patch",
            ".github/objc876/0003-objc4-876-full-dyld-priv.patch",
            ".github/objc876/PATCHES.sha256",
            ".github/objc876/LOCAL_COMPAT_HEADERS.json",
            ".github/objc876/OBJC876_HEADERS.json",
            ".github/objc876/HEADER_PROBE_CONTEXT.json",
            ".github/objc876/PUBLIC_HEADERS.json",
            ".github/objc876/RUNNER_IMAGE.json",
            ".github/objc876/RUNNER_IMAGE.sha256",
            ".github/objc876/objc4-876-dyld-spi.patch.gz",
            ".github/objc876/runner-inventory/README.md.gz",
            ".github/objc876/runner-inventory/macos-15-Readme.md.gz",
        }
        header_files = {".github/objc876/public-headers/" + p["stored_path"]
                        for p in MODULE.ALL_HEADER_POLICIES.values()}
        return fixed_objc_files | header_files | {
            ".github/scripts/build_objc876_apple.py",
            ".github/scripts/test_build_objc876_apple.py",
            ".github/workflows/objc876-apple-clang.yml",
        }

    def checksum_file(self, root, relative):
        values = {}
        for line in (root / relative).read_text().splitlines():
            digest, path = line.split("  ", 1)
            self.assertNotIn(path, values)
            values[path] = digest
        return values

    def audit_proposal_files(self, root):
        expected_files = self.proposal_expected_files()
        objc_fixed_relative = {
                "0001-objc4-876-darling-source-compat.patch.gz",
                "0002-objc4-876-darling-cmake-graph.patch",
                "0003-objc4-876-full-dyld-priv.patch",
                "PATCHES.sha256", "PUBLIC_HEADERS.json", "LOCAL_COMPAT_HEADERS.json",
                "OBJC876_HEADERS.json", "HEADER_PROBE_CONTEXT.json",
                "RUNNER_IMAGE.json", "RUNNER_IMAGE.sha256",
                "objc4-876-dyld-spi.patch.gz", "runner-inventory/README.md.gz",
                "runner-inventory/macos-15-Readme.md.gz",
        }
        header_relative = {"public-headers/" + p["stored_path"]
                           for p in MODULE.ALL_HEADER_POLICIES.values()}
        expected_objc_files = objc_fixed_relative | header_relative
        expected_objc_dirs = {"runner-inventory", "public-headers"} | {
            "public-headers/" + str(parent) for name in MODULE.ALL_HEADER_POLICIES
            for parent in Path(name).parents if str(parent) != "."
        }
        objc_entries = MODULE.enumerate_directory(root / ".github/objc876")
        self.assertEqual(objc_entries, {"files": expected_objc_files,
                                        "directories": expected_objc_dirs})
        actual_files = {
            ".github/objc876/" + name for name in objc_entries["files"]
        }
        actual_files.update({
            ".github/scripts/build_objc876_apple.py",
            ".github/scripts/test_build_objc876_apple.py",
            ".github/workflows/objc876-apple-clang.yml",
        })
        self.assertEqual(actual_files, expected_files)
        expected_hashes = self.checksum_file(
            root, ".github/objc876/PATCHES.sha256"
        ) | self.checksum_file(root, ".github/objc876/RUNNER_IMAGE.sha256")
        expected_hashes.update(PINNED_RECIPE_HASHES)
        expected_hashes[".github/objc876/RUNNER_IMAGE.sha256"] = \
            "85a841d5875f238b96c43fbcd683460c9e091d88203cd9ad9762bd8ccbe22a87"
        expected_hashes[".github/workflows/objc876-apple-clang.yml"] = \
            "901b0886f4f475bb9164c7d3334b5dbfae0b3b03c4fb2d21159cf712fe119e91"
        for relative in sorted(expected_files):
            path = root / relative
            info = path.lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode), relative)
            self.assertFalse(path.is_symlink(), relative)
            if relative in expected_hashes:
                self.assertEqual(MODULE.sha256(path), expected_hashes[relative], relative)
            result = subprocess.run(
                ["git", "diff", "--no-index", "--check", "/dev/null", relative],
                cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            self.assertIn(result.returncode, (0, 1))
            self.assertEqual(result.stdout, "", relative + "\n" + result.stdout)

    def test_exact_proposal_file_set_and_whitespace(self):
        self.audit_proposal_files(ROOT)

    def test_proposal_audit_is_independent_of_git_tracking_and_rejects_drift(self):
        expected = self.proposal_expected_files()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in expected:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            self.audit_proposal_files(root)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Policy Test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "policy@example.invalid"],
                           cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "tracked proposal"], cwd=root, check=True)
            self.audit_proposal_files(root)
            extra = root / ".github/objc876/extra"
            extra.write_text("extra\n")
            with self.assertRaises(AssertionError):
                self.audit_proposal_files(root)
            extra.unlink()
            missing = root / ".github/objc876/PUBLIC_HEADERS.json"
            saved = missing.read_bytes()
            missing.unlink()
            with self.assertRaises((AssertionError, FileNotFoundError)):
                self.audit_proposal_files(root)
            missing.write_bytes(saved)
            self.audit_proposal_files(root)


if __name__ == "__main__":
    unittest.main()
