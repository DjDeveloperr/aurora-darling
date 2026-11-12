import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess

HERE = Path(__file__).resolve().parent
REPORT = {"schema": "aurora_iosurface_reference_v1", "attempts": 0,
          "target_limit": "Reference runner only; not macOS13.5 ARM64 validation"}

def run(argv, timeout):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, check=False)

def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))

def main():
    for label, command, pattern in [
        ("os_version", ["/usr/bin/sw_vers", "-productVersion"], r"[0-9]+(?:\.[0-9]+){1,2}"),
        ("architecture", ["/usr/bin/uname", "-m"], r"(?:x86_64|arm64)")]:
        result = run(command, 10)
        value = result.stdout.decode("ascii", errors="strict").strip()
        if result.returncode or not re.fullmatch(pattern, value):
            raise RuntimeError("invalid host metadata")
        REPORT[label] = value
    if REPORT["architecture"] != "arm64":
        REPORT["admission"] = "wrong_architecture"
        return
    if REPORT["os_version"] != "15.8.2":
        REPORT["admission"] = "wrong_baseline_version"
        return
    REPORT["admission"] = "arm64_same_version"
    source = HERE / "iosurface-init.c"
    REPORT["source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    binary = HERE / "iosurface-init"
    result = run(["/usr/bin/xcrun", "clang", "-std=c11", "-O1", "-Wall", "-Wextra",
                  "-Werror", "-Wno-deprecated-declarations", str(source), "-framework",
                  "IOKit", "-framework", "CoreFoundation", "-framework", "IOSurface", "-o", str(binary)], 60)
    REPORT["compile_status"] = result.returncode
    REPORT["compile_stderr_bytes"] = len(result.stderr)
    REPORT["compile_stderr_sha256"] = hashlib.sha256(result.stderr).hexdigest()
    if result.returncode:
        return
    # Apple WebKit's published sandbox profiles use this IOSurface-only client filter.
    profile = """(version 1)
(allow default)
(deny network*)
(deny file-write*)
(deny iokit-open)
(allow iokit-open (iokit-user-client-class "IOSurfaceRootUserClient"))
"""
    result = run(["/usr/bin/sandbox-exec", "-p", profile, "/usr/bin/true"], 10)
    REPORT["sandbox_profile_status"] = result.returncode
    if result.returncode:
        return
    REPORT["attempts"] = 1
    result = subprocess.run(["/usr/bin/sandbox-exec", "-p", profile, str(binary)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=15, check=False, preexec_fn=child_limits,
        env={"PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"], "TMPDIR": os.environ["TMPDIR"]})
    REPORT["process_status"] = result.returncode
    REPORT["stderr_bytes"] = len(result.stderr)
    REPORT["stderr_sha256"] = hashlib.sha256(result.stderr).hexdigest()
    if len(result.stdout) > 4096:
        raise RuntimeError("output limit")
    notes = [json.loads(line) for line in result.stdout.splitlines()]
    contexts = [note for note in notes if note.get("schema") == "iosurface_public_context_v1"]
    if len(contexts) != 1 or type(contexts[0].get("created")) is not bool:
        raise RuntimeError("context schema")
    context = contexts[0]
    if set(context) - {"schema", "created", "width", "height", "bytes_per_element", "allocation_size"}:
        raise RuntimeError("context keys")
    for key in ("width", "height", "bytes_per_element", "allocation_size"):
        if key in context and (type(context[key]) is not int or not 0 <= context[key] <= 1024*1024):
            raise RuntimeError("context value")
    REPORT["public_context"] = context
    if not context["created"]:
        if len(notes) != 1:
            raise RuntimeError("private call after failed context")
        return
    boundaries = [note for note in notes if note.get("schema") == "iosurface_init_boundary_v1"]
    if len(notes) != 2 or len(boundaries) != 1:
        raise RuntimeError("boundary count")
    note = boundaries[0]
    allowed = {"schema", "matched", "open_status", "service_release_status", "call_status",
               "returned_size", "changed_bytes", "zero_bytes", "guards_intact", "close_status"}
    if not isinstance(note, dict) or not set(note) <= allowed:
        raise RuntimeError("output schema")
    if note.get("schema") != "iosurface_init_boundary_v1" or type(note.get("matched")) is not bool:
        raise RuntimeError("output schema")
    for key, value in note.items():
        if key in {"schema", "matched", "guards_intact"}:
            continue
        if type(value) is not int or not 0 <= value <= 2**64-1:
            raise RuntimeError("output value")
    if "guards_intact" in note and type(note["guards_intact"]) is not bool:
        raise RuntimeError("guard value")
    if note.get("changed_bytes", 0) > 24 or note.get("zero_bytes", 0) > 24:
        raise RuntimeError("output count")
    REPORT["boundary"] = note

try:
    main()
except Exception as error:
    REPORT["error_type"] = type(error).__name__
finally:
    print("AURORA_IOSURFACE_REFERENCE_JSON=" + json.dumps(REPORT, sort_keys=True))
