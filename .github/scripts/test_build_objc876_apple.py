#!/usr/bin/env python3
import importlib.util
import json
import os
import re
import shutil
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


class AppleBuildPolicyTests(unittest.TestCase):
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

    def test_verified_patch_hashes(self):
        observed = MODULE.verify_inputs(ROOT / ".github/objc876")
        self.assertEqual(
            observed["dyld_spi"]["content_sha256"],
            MODULE.DYLD_SPI_INPUT["content_sha256"],
        )
        self.assertEqual(len(observed["port_patches"]), 2)
        headers = MODULE.verify_public_headers(ROOT / ".github/objc876/public-headers")
        self.assertEqual(set(headers), {"mach-o/dyld_priv.h", "sys/reason.h"})
        dyld = headers["mach-o/dyld_priv.h"]
        self.assertEqual(dyld["sha256"],
                         "82eb5bcf0dd6f8fa1305c69110b2e7c333b74375433d8216d7a29452a7374ac8")
        self.assertEqual(dyld["stored_sha256"],
                         "c26fbc499831bdf43b5158462438bf83a138d6baf694b7e14e87e3966d3ac502")
        reason = headers["sys/reason.h"]
        self.assertEqual(reason["sha256"],
                         "782540658b7d4af1fb7278de7868874e374db6c35af5be9756a19ee4b6983cb3")
        self.assertEqual(reason["stored_sha256"], reason["sha256"])

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
        for policy in MODULE.PUBLIC_HEADERS.values():
            target = public / policy["stored_path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / ".github/objc876/public-headers" / policy["stored_path"],
                         target)
        shutil.copy2(ROOT / ".github/objc876/PUBLIC_HEADERS.json",
                     root / "PUBLIC_HEADERS.json")
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
            self.assertEqual(entries, {
                "files": {"mach-o/dyld_priv.h", "sys/reason.h"},
                "directories": {"mach-o", "sys"},
            })
            for name, policy in MODULE.PUBLIC_HEADERS.items():
                self.assertEqual(MODULE.sha256(output / name), policy["sha256"])

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

    def test_workflow_checksum_command_from_repository_root(self):
        result = subprocess.run(
            ["shasum", "-a", "256", "-c", ".github/objc876/PATCHES.sha256"],
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

    def test_all_compatibility_tus_compile_with_private_bases_outside_sdk(self):
        compiler = shutil.which("clang++")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compat = root / "compat"
            public = root / "public"
            sdk = root / "sdk"
            for name in MODULE.PATCH_COMPAT_HEADERS:
                path = compat / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.added_compat_header(name))
            (public / "sys").mkdir(parents=True)
            shutil.copy2(ROOT / ".github/objc876/public-headers/sys/reason.h",
                         public / "sys/reason.h")
            (public / "mach-o").mkdir(parents=True)
            (public / "mach-o/dyld_priv.h").write_text(
                "#include <stdint.h>\nstruct mach_header;\n"
            )
            sdk_headers = {
                "stdint.h": ("#define __BEGIN_DECLS extern \"C\" {\n#define __END_DECLS }\n"
                              "typedef unsigned int uint32_t; typedef unsigned long uintptr_t; "
                              "typedef unsigned long long uint64_t;\n#define UINT32_MAX 0xffffffffU\n"),
                "TargetConditionals.h": "#define TARGET_OS_EXCLAVEKIT 0\n",
                "mach-o/dyld.h": "#include <stdint.h>\nstruct mach_header;\n",
                "ptrauth.h": ("#include <stdint.h>\n#define ptrauth_key_process_independent_data 2\n"
                              "#define ptrauth_key_process_dependent_data 3\n"),
            }
            for name, contents in sdk_headers.items():
                path = sdk / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            for index, name in enumerate(MODULE.HEADER_PROBE_NAMES):
                source = root / f"probe-{index}.mm"
                source.write_text(f"#include <{name}>\nint probe{index}(void) {{ return 0; }}\n")
                result = subprocess.run(
                    [compiler, "-std=gnu++14", "-fsyntax-only", "-nostdinc",
                     "-I" + str(compat), "-I" + str(public), "-I" + str(sdk), str(source)],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                )
                self.assertEqual(result.returncode, 0, name + "\n" + result.stdout)

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

    def test_exact_proposal_file_set_and_whitespace(self):
        expected_files = {
            ".github/objc876/0001-objc4-876-darling-source-compat.patch.gz",
            ".github/objc876/0002-objc4-876-darling-cmake-graph.patch",
            ".github/objc876/PATCHES.sha256",
            ".github/objc876/PUBLIC_HEADERS.json",
            ".github/objc876/objc4-876-dyld-spi.patch.gz",
            ".github/objc876/public-headers/mach-o/dyld_priv.h.gz",
            ".github/objc876/public-headers/sys/reason.h",
            ".github/scripts/build_objc876_apple.py",
            ".github/scripts/test_build_objc876_apple.py",
            ".github/workflows/objc876-apple-clang.yml",
        }
        objc_entries = MODULE.enumerate_directory(ROOT / ".github/objc876")
        self.assertEqual(objc_entries, {
            "files": {
                "0001-objc4-876-darling-source-compat.patch.gz",
                "0002-objc4-876-darling-cmake-graph.patch",
                "PATCHES.sha256", "PUBLIC_HEADERS.json",
                "objc4-876-dyld-spi.patch.gz", "public-headers/mach-o/dyld_priv.h.gz",
                "public-headers/sys/reason.h",
            },
            "directories": {"public-headers", "public-headers/mach-o", "public-headers/sys"},
        })
        actual_files = {
            ".github/objc876/" + name for name in objc_entries["files"]
        }
        actual_files.update({
            ".github/scripts/build_objc876_apple.py",
            ".github/scripts/test_build_objc876_apple.py",
            ".github/workflows/objc876-apple-clang.yml",
        })
        self.assertEqual(actual_files, expected_files)
        untracked = set(subprocess.check_output(
            ["git", "ls-files", "--others", "--exclude-standard"], cwd=ROOT, text=True
        ).splitlines())
        self.assertEqual(untracked, {
            ".github/objc876/public-headers/mach-o/dyld_priv.h.gz",
        })
        for relative in sorted(expected_files):
            result = subprocess.run(
                ["git", "diff", "--no-index", "--check", "/dev/null", relative],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            self.assertIn(result.returncode, (0, 1))
            self.assertEqual(result.stdout, "", relative + "\n" + result.stdout)


if __name__ == "__main__":
    unittest.main()
