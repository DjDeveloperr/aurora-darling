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
    return observed


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


def normalize(argv, substitutions):
    result = []
    ordered = sorted(substitutions.items(), key=lambda item: len(item[0]), reverse=True)
    for argument in argv:
        value = str(argument)
        for actual, token in ordered:
            value = value.replace(actual, token)
        result.append(value)
    return result


def common_flags(source, build, sdk):
    return [
        "-target", TARGET, "-arch", "arm64e", "-mmacosx-version-min=" + MIN_OS,
        "-isysroot", str(sdk), "-I" + str(build / "include"),
        "-I" + str(source / "runtime/compat"), "-I" + str(source / "runtime"),
        "-D__DARWIN_UNIX03", "-DDARLING", "-DDARWIN", "-DPLATFORM_MacOSX",
        "-DTARGET_OS_IPHONE=0", "-DTARGET_OS_MAC=1", "-DOBJC_IS_DEBUG_BUILD=0",
        "-DOBJC_NO_GC", "-DOS_OBJECT_USE_OBJC=0", "-D__STDC_NO_ATOMICS__",
        "-DDARLING_OBJC_VM_MAX_ADDRESS=0x00007ffffffffff8ULL", "-O2", "-DNDEBUG",
        "-g0", "-fPIC", "-fblocks", "-fobjc-legacy-dispatch", "-fvisibility=hidden",
        "-fstrict-aliasing", "-fno-delete-null-pointer-checks",
        "-Wno-nullability-completeness", "-Wno-deprecated-declarations",
        "-Wno-availability", "-Wno-invalid-offsetof", "-Wno-c++11-narrowing",
        "-Wno-unused-command-line-argument",
    ]


def feature_probe(source, build, clangxx, flags):
    probe = build / "restricted-ptrauth.mm"
    probe.write_text(
        "#include <stdint.h>\n"
        "#include \"objc-ptrauth.h\"\n"
        "#if !__has_feature(ptrauth_calls)\n#error ptrauth_calls_required\n#endif\n"
        "#if !__has_feature(ptrauth_restricted_intptr_qualifier)\n"
        "#error restricted_intptr_required\n#endif\n"
        "uintptr_t ptrauth_class_rx_enforce auroraClassRX;\n"
        "uintptr_t ptrauth_trampoline_textSegment auroraTextSegment;\n"
        "int auroraRestrictedPtrauthControl(void) { return 0; }\n",
        encoding="utf-8",
    )
    argv = [str(clangxx), *flags, "-std=gnu++14", "-fno-rtti", "-fno-exceptions",
            "-c", str(probe), "-o", str(build / "restricted-ptrauth.o")]
    run(argv)
    return argv


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


def build(source, patch_dir, build_dir, artifact, developer):
    verify_source(source)
    input_hashes = verify_inputs(patch_dir)
    apply_patches(source, patch_dir)
    build_dir.mkdir(parents=True)
    artifact.mkdir(parents=True)
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
    flags = common_flags(source, build_dir, sdk)
    commands = []
    commands.append(feature_probe(source, build_dir, clangxx, flags))
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
        str(clangxx): "$CLANGXX", str(clang): "$CLANG", str(developer): "$DEVELOPER",
        str(patch_dir.parent.parent): "$REPO",
    }
    normalized = [normalize(command, substitutions) for command in commands]
    (artifact / "build-argv.json").write_text(
        json.dumps(normalized, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    compiler_version = output([str(clang), "--version"]).splitlines()[0]
    provenance = {
        "schema": "aurora_objc876_apple_clang_v1",
        "source": {"repository": "apple-oss-distributions/objc4",
                   "commit": OBJC_COMMIT, "tree": OBJC_TREE},
        "reviewed_inputs": input_hashes,
        "compiler": {"version": compiler_version, "sha256": sha256(clang)},
        "xcode": list(xcode_version),
        "sdk": {"name": SDK_NAME, "version": sdk_version},
        "target": TARGET,
        "minimum_os": MIN_OS,
        "restricted_intptr_feature_probe": True,
        "production_object_count": len(objects),
        "validation": {"architecture": "arm64e", "install_name": "/usr/lib/libobjc.A.dylib",
                       "required_export_count": len(required), "missing_required_exports": 0},
        "libobjc": {"bytes": dylib.stat().st_size, "sha256": sha256(dylib)},
    }
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
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    verify_inputs(args.patch_dir)
    if args.validate_only:
        if len(RUNTIME_SOURCES) != 33 or len(set(RUNTIME_SOURCES)) != 33:
            raise RuntimeError("production source graph is not exactly 33 unique objects")
        if ARTIFACT_FILES != {"libobjc.A.dylib", "build-argv.json", "provenance.json", "SHA256SUMS"}:
            raise RuntimeError("artifact allowlist changed")
        print("objc876 Apple-Clang proposal validation: PASS")
        return
    required = (args.source, args.build_dir, args.artifact, args.developer_dir)
    if any(value is None for value in required):
        parser.error("build mode requires source, build-dir, artifact, and developer-dir")
    if args.build_dir.exists() or args.artifact.exists():
        raise RuntimeError("build and artifact directories must not pre-exist")
    build(args.source, args.patch_dir, args.build_dir, args.artifact, args.developer_dir)


if __name__ == "__main__":
    main()
