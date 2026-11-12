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
    source = HERE / "iosurface-init.c"
    REPORT["source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    binary = HERE / "iosurface-init"
    result = run(["/usr/bin/xcrun", "clang", "-std=c11", "-O1", "-Wall", "-Wextra",
                  "-Werror", "-Wno-deprecated-declarations", str(source), "-framework",
                  "IOKit", "-framework", "CoreFoundation", "-o", str(binary)], 60)
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
    note = json.loads(result.stdout)
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
