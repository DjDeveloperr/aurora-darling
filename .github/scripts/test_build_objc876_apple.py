#!/usr/bin/env python3
import importlib.util
import re
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
        expected = {
            ".github/objc876/0001-objc4-876-darling-source-compat.patch.gz",
            ".github/objc876/0002-objc4-876-darling-cmake-graph.patch",
            ".github/objc876/PATCHES.sha256",
            ".github/objc876/objc4-876-dyld-spi.patch.gz",
            ".github/scripts/build_objc876_apple.py",
            ".github/scripts/test_build_objc876_apple.py",
            ".github/workflows/objc876-apple-clang.yml",
        }
        actual = {
            str(path.relative_to(ROOT)) for path in (ROOT / ".github/objc876").iterdir()
            if path.is_file()
        }
        actual.update({
            ".github/scripts/build_objc876_apple.py",
            ".github/scripts/test_build_objc876_apple.py",
            ".github/workflows/objc876-apple-clang.yml",
        })
        self.assertEqual(actual, expected)
        untracked = set(subprocess.check_output(
            ["git", "ls-files", "--others", "--exclude-standard"], cwd=ROOT, text=True
        ).splitlines())
        self.assertEqual(untracked, expected)
        for relative in sorted(expected):
            result = subprocess.run(
                ["git", "diff", "--no-index", "--check", "/dev/null", relative],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            self.assertIn(result.returncode, (0, 1))
            self.assertEqual(result.stdout, "", relative + "\n" + result.stdout)


if __name__ == "__main__":
    unittest.main()
