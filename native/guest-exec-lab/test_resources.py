#!/usr/bin/env python3
"""Compare native and Shroot resource ownership under the selected shell UID."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shlex
import statistics
import tomllib
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--config", type=Path, default=Path.home() / ".codex/config.toml")
    parser.add_argument("--server", default="magicdesk")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--case", choices=("all", "kernel-baseline", "mapping-task", "pidfd-table", "proc-custody", "exec-custody", "open-job", "ofd-order", "fd-handoff", "fd-parcel", "fd-messages", "ipc-peer", "fd-custody", "fd-custody-dirfd", "fd-custody-nofollow", "fd-lifecycle", "fs-dispatch", "fs-buffer", "fs-results", "fs-export", "fs-return", "fs-directory", "fs-capture", "rpc", "stores"), default="all",
                        help="Run resource regressions, FD handoff/parcel, terminal RPC custody, native FD lifecycle, or worker transport")
    parser.add_argument("--compare-installed", action="store_true",
                        help="Compare identical metadata/spawn fixtures with the installed runtime")
    args = parser.parse_args()
    if args.case != "all" and args.compare_installed:
        parser.error("--compare-installed requires the full resource suite")
    repo = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("md_mcp", repo / "scripts/mcp-client.py")
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    config = tomllib.loads(args.config.read_text())["mcp_servers"][args.server]
    client = transport.Client(config["url"], config["http_headers"]["Authorization"].removeprefix("Bearer "),
                              request_timeout=120)
    state = client.call("get_state")
    if state.get("shell", {}).get("uid") != 2000:
        raise RuntimeError("Select shell explicitly; this test never elevates")
    root = "/data/local/tmp/md-resources-" + uuid.uuid4().hex
    session = client.call("console.open", {"directory": "/data/local/tmp"})["sessionId"]
    result = {"device": state["device"], "app": state["app"], "root": root, "case": args.case, "checks": []}

    def check(name, command, contains=None, patterns=(), exit_code=0, absent_patterns=()):
        entry = {"name": name, "command": command, "passed": False}
        result["checks"].append(entry)
        try:
            value = client.call("console.execute", {"sessionId": session, "command": command})
        except Exception as error:
            entry["error"] = str(error)
            raise
        passed = value["exitCode"] == exit_code and (contains is None or contains in value["output"])
        passed = passed and all(re.search(pattern, value["output"]) for pattern in patterns)
        passed = passed and not any(re.search(pattern, value["output"]) for pattern in absent_patterns)
        entry.update(passed=passed, **value)
        print(("PASS " if passed else "FAIL ") + name + "\n" + value["output"], flush=True)
        if not passed:
            raise RuntimeError(name)
        return value

    def check_kernel_workflows():
        runner = root + "/libmagicdesk_guest_kernel_baseline.so " + root + "/libmagicdesk_guest_run.so --store " + root + "/store --deadline-seconds 90 -- /bin/test "
        for case, message in (("proc-thread-capture", "PASS proc task capture"),
                              ("buffer-descriptors", "PASS buffered descriptors"),
                              ("buffer-data", "PASS buffered data inputs"),
                              ("buffer-import", "PASS buffered imported dirfd")):
            check("guest without thread pidfds " + case, runner + case + " /tmp", message)

    def check_buffer_descriptors():
        check("native xattr with full table", root + "/libmagicdesk_guest_resource_guest.so xattr-slots-native "
              + root + "/native", "PASS xattr without private FDs")
        check("guest xattr with full table", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test xattr-slots /tmp", "PASS xattr without private FDs")
        check("native watches with full table", root + "/libmagicdesk_guest_resource_guest.so watch-slots "
              + root + "/native", "PASS watch paths without private FDs")
        check("guest watches with full table", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test watch-slots /tmp", "PASS watch paths without private FDs")
        check("native imported dirfd", root + "/libmagicdesk_guest_resource_guest.so buffer-import "
              + root + "/native", "PASS buffered imported dirfd")
        check("guest imported dirfd", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test buffer-import /tmp", "PASS buffered imported dirfd")
        check("native data input control", root + "/libmagicdesk_guest_resource_guest.so buffer-data "
              + root + "/native", "PASS buffered data inputs")
        check("guest buffered data input", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test buffer-data /tmp", "PASS buffered data inputs")
        check("native buffered descriptors", root + "/libmagicdesk_guest_resource_guest.so buffer-descriptors "
              + root + "/native", "PASS buffered descriptors")
        check("guest buffered descriptors", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test buffer-descriptors /tmp", "PASS buffered descriptors")
        check("guest mapped FIFO", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test buffer-fifo /tmp", "PASS mapped FIFO")

    def check_captures():
        check("native private-thread proc selection", root + "/libmagicdesk_guest_resource_guest.so proc-thread-capture "
              + root + "/native", "PASS proc task capture")
        check("guest private-thread proc selection", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test proc-thread-capture /tmp", "PASS proc task capture")
        check("native capture terminal control", root + "/libmagicdesk_guest_resource_guest.so capture-terminal-native "
              + root + "/native", "PASS capture terminal ownership")
        check("guest capture terminal ownership", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test capture-terminal /tmp", "PASS capture terminal ownership")
        check("native unknown cwd control", root + "/libmagicdesk_guest_resource_guest.so native-cwd "
              + root + "/native", "PASS native cwd")
        check("guest unknown cwd capture", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test native-cwd /tmp", "PASS native cwd",
              patterns=(r"PROBE buffer-capture pid=\d+",))
        check("native proc watch full table", root + "/libmagicdesk_guest_resource_guest.so watch-slots "
              + root + "/native", "PASS watch paths without private FDs")
        check("guest proc watch full table", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test watch-slots /tmp", "PASS watch paths without private FDs")

    def check_buffers():
        check_captures()
        check("adapter address-space ownership", root + "/libmagicdesk_guest_test_interception_buffers.so",
              "PASS shared request buffer ownership")
        check("native buffered cwd control", root + "/libmagicdesk_guest_resource_guest.so buffer-cwd " + root + "/native",
              "PASS buffered cwd")
        check("guest buffer lifecycle", root + "/libmagicdesk_guest_run.so --store " + root
              + "/store --deadline-seconds 90 -- /bin/test buffer-cwd /tmp", "PASS buffered cwd")
        check("native buffered open control", root + "/libmagicdesk_guest_resource_guest.so buffer-open " + root + "/native",
              "PASS buffered O_PATH")
        check("guest buffered O_PATH", root + "/libmagicdesk_guest_run.so --store " + root
              + "/store --deadline-seconds 90 -- /bin/test buffer-open /tmp", "PASS buffered O_PATH")
        check_buffer_descriptors()
        check_exports()
        check_returns()
        check_directories()
        for suffix in ("", "-protected"):
            check("native buffered paths" + suffix, root + "/libmagicdesk_guest_resource_guest.so buffer-paths"
                  + suffix + " " + root + "/native", "PASS buffered paths")
            check("guest buffered paths" + suffix, root + "/libmagicdesk_guest_run.so --store " + root
                  + "/store --deadline-seconds 90 -- /bin/test buffer-paths" + suffix + " /tmp", "PASS buffered paths")
        for suffix in ("", "-dirfd", "-nofollow"):
            check("native buffered custody control" + suffix,
                  root + "/libmagicdesk_guest_resource_guest.so custody-native" + suffix + " " + root + "/native",
                  "PASS terminal RPC custody")
            check("guest buffered custody" + suffix, root + "/libmagicdesk_guest_run.so --store " + root
                  + "/store --deadline-seconds 90 -- /bin/test custody" + suffix + " /tmp", "PASS terminal RPC custody")
        check_exec_custody()
        check_proc_custody()
        check("native buffered group exit", root + "/libmagicdesk_guest_resource_guest.so buffer-exit " + root + "/native",
              "PASS buffered group exit")
        # EVENT_WAIT: the outer bound also covers failure inside supervisor cleanup.
        check("guest buffered group exit", "timeout -k 5 105 " + root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test buffer-exit /tmp", "PASS buffered group exit")
        for suffix in ("", "-protected"):
            # EVENT_WAIT: idle tree expiry must reap terminal stops. An outer
            # timeout has a different exit code and cannot count as cleanup.
            check("guest terminal cleanup" + suffix, "timeout -k 5 15 " + root
                  + "/libmagicdesk_guest_run.so --diagnostics --store " + root
                  + "/store --deadline-seconds 1 -- /bin/test buffer-park" + suffix + " /tmp",
                  "READY buffered parked group",
                  patterns=(r"supervisor failure line=\d+ outcome >= 0 errno=110",), exit_code=125)

    def check_exec_custody():
        check("native exec preparation control", root + "/libmagicdesk_guest_resource_guest.so exec-custody-native "
              + root + "/native", "PASS exec preparation custody")
        check("guest exec preparation custody", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test exec-custody /tmp", "PASS exec preparation custody")

    def check_proc_custody():
        check("native imported cwd with full table", root + "/libmagicdesk_guest_resource_guest.so imported-cwd "
              + root + "/native", "PASS imported cwd")
        check("guest imported cwd with full table", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test imported-cwd /tmp", "PASS imported cwd")
        check("native executable metadata with full table", root + "/libmagicdesk_guest_resource_guest.so proc-exe-slots "
              + root + "/native", "PASS executable metadata")
        check("guest executable metadata with full table", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test proc-exe-slots /tmp", "PASS executable metadata")
        check("native foreign proc open with one slot", root + "/libmagicdesk_guest_resource_guest.so proc-open-slots "
              + root + "/native", "PASS foreign proc open")
        check("guest foreign proc open with one slot", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test proc-open-slots /tmp", "PASS foreign proc open")
        check("native foreign proc link with full table", root + "/libmagicdesk_guest_resource_guest.so proc-link-slots "
              + root + "/native", "PASS foreign proc link")
        check("guest foreign proc link with full table", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test proc-link-slots /tmp", "PASS foreign proc link")
        check("native proc reopen with one slot", root + "/libmagicdesk_guest_resource_guest.so proc-reopen-slots "
              + root + "/native", "PASS proc reopen with one slot")
        check("guest proc reopen with one slot", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test proc-reopen-slots /tmp", "PASS proc reopen with one slot")
        check("native metadata with full table", root + "/libmagicdesk_guest_resource_guest.so metadata-slots-native "
              + root + "/native", "PASS metadata without private FDs")
        check("guest metadata with full table", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test metadata-slots /tmp", "PASS metadata without private FDs")
        for guest in (False, True):
            check(("guest" if guest else "native") + " umask custody", root
                  + ("/libmagicdesk_guest_run.so --diagnostics --store " + root
                     + "/store --deadline-seconds 90 -- /bin/test umask-custody /tmp" if guest
                     else "/libmagicdesk_guest_resource_guest.so umask-custody-native " + root + "/native"),
                  "PASS umask custody")
        check("native proc snapshot control", root + "/libmagicdesk_guest_resource_guest.so proc-custody-native "
              + root + "/native", "PASS proc snapshot custody")
        check("guest proc snapshot custody", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test proc-custody /tmp", "PASS proc snapshot custody")
        check("guest proc snapshot semantics", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test proc-snapshot /tmp", "PASS proc snapshots")
        check("native mount snapshot O_PATH", root + "/libmagicdesk_guest_resource_guest.so proc-mount-paths "
              + root + "/native", "PASS mount snapshot O_PATH")
        check("guest mount snapshot O_PATH", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test proc-mount-paths /tmp", "PASS mount snapshot O_PATH")

    def check_exports():
        check("native metadata export control", root + "/libmagicdesk_guest_resource_guest.so metadata-export-native "
              + root + "/native", "PASS metadata export custody")
        check("guest protected metadata export", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test metadata-export /tmp", "PASS metadata export custody")
        check("native protected export control", root + "/libmagicdesk_guest_resource_guest.so buffer-export-native "
              + root + "/native", "PASS protected export")
        check("guest protected export", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test buffer-export /tmp", "PASS protected export")

    def check_returns():
        check("native protected return control", root + "/libmagicdesk_guest_resource_guest.so buffer-return-native "
              + root + "/native", "PASS protected return")
        check("guest protected descriptor return", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --bind /dev /attached --deadline-seconds 90 -- /bin/test buffer-return /tmp", "PASS protected return")

    def check_directories():
        check("native directory copy", root + "/libmagicdesk_guest_resource_guest.so buffer-directory "
              + root + "/native", "PASS protected directory copy")
        check("guest directory copy", root + "/libmagicdesk_guest_run.so --diagnostics --store " + root
              + "/store --deadline-seconds 90 -- /bin/test buffer-directory /tmp", "PASS protected directory copy")

    try:
        check("isolated staging", "mkdir -m 700 " + root)
        names = ("fd_handoff",) if args.case in ("fd-handoff", "fd-parcel", "fd-messages") else (
            "bootstrap", "supervisor", "run", "service", "resource_guest", "root_guest",
            "test_task_resources", "test_inodes", "test_mounts", "test_credentials", "test_rpc", "test_snapshot", "fd_handoff", "test_ipc_peer")
        if args.case in ("proc-custody", "exec-custody", "fd-custody", "fd-custody-dirfd", "fd-custody-nofollow", "fs-buffer", "fs-results", "fs-export", "fs-return", "fs-directory", "fs-capture"):
            names = ("bootstrap", "supervisor", "run", "service", "resource_guest")
        if args.case in ("all", "fs-buffer"):
            names += ("test_interception_buffers",)
        if args.case == "all":
            names += ("test_open_job", "fs_dispatch", "test_launch_registry")
        if args.case in ("all", "kernel-baseline"):
            names += ("kernel_baseline", "capabilities")
        if args.case == "open-job":
            names = ("test_open_job",)
        if args.case == "fd-lifecycle":
            names = ("fd_lifecycle",)
        if args.case == "mapping-task":
            names = ("mapping_task",)
        if args.case == "fs-dispatch":
            names = ("fs_dispatch", "test_interception_buffers")
        if args.case == "rpc":
            names = ("test_rpc",)
        if args.case == "stores":
            names = ("test_mounts", "test_inodes", "test_snapshot")
        if args.case == "ipc-peer":
            names = ("test_ipc_peer", "fs_dispatch", "test_launch_registry")
        if args.case == "ofd-order":
            names = ("test_task_resources",)
        if args.case == "pidfd-table":
            names = ("pidfd_table",)
        for name in names:
            file = "libmagicdesk_guest_" + name + ".so"
            transport.upload(client, args.build / file, root + "/" + file)
        check("prepare fixtures", "chmod 700 " + root + "/*.so")
        if args.case in ("all", "ipc-peer"):
            check("launch registry lifetime", root + "/libmagicdesk_guest_test_launch_registry.so",
                  "PASS launch ownership")
            check("private IPC peer negotiation", root + "/libmagicdesk_guest_test_ipc_peer.so " + root + "/peer",
                  "PASS private IPC peer negotiation")
            check("asynchronous IPC peer admission", root + "/libmagicdesk_guest_fs_dispatch.so --ipc-peer " + root + "/peer-store",
                  "PASS asynchronous IPC peer admission")
            if args.case == "ipc-peer":
                return
        if args.case == "stores":
            for name in ("mounts", "inodes", "snapshot"):
                check(name + " model", root + "/libmagicdesk_guest_test_" + name + ".so " + root + "/model-" + name)
            return
        if args.case in ("all", "kernel-baseline"):
            check("mandatory capability admission", root + "/libmagicdesk_guest_capabilities.so "
                  + root + "/libmagicdesk_guest_supervisor.so " + root + "/libmagicdesk_guest_bootstrap.so",
                  "PASS capability isolation")
            check("exact task kernel baseline", root + "/libmagicdesk_guest_kernel_baseline.so",
                  "PASS exact task kernel baseline")
            check("resource model without thread pidfds", root + "/libmagicdesk_guest_kernel_baseline.so "
                  + root + "/libmagicdesk_guest_test_task_resources.so", "PASS resource ownership")
        if args.case == "kernel-baseline":
            check("fixture directories", "mkdir -p " + root + "/source/tmp " + root + "/source/bin")
            check("stage guest image", "cp " + root + "/libmagicdesk_guest_resource_guest.so " + root + "/source/bin/test")
            check("import fixture", root + "/libmagicdesk_guest_service.so --import " + root + "/source " + root + "/store")
            check_kernel_workflows()
            return
        if args.case == "pidfd-table":
            result["experiment"] = {"productionAdapter": False, "requiresThreadPidfd": True}
            check("same-group private-table pidfd", root + "/libmagicdesk_guest_pidfd_table.so "
                  + root + "/pidfd", "PASS same-group private-table pidfd feasibility")
            return
        if args.case in ("all", "open-job"):
            check("deferred open ownership", root + "/libmagicdesk_guest_test_open_job.so",
                  "PASS deferred open ownership")
            if args.case == "open-job":
                return
        if args.case == "ofd-order":
            check("active OFD ordering", root + "/libmagicdesk_guest_test_task_resources.so",
                  "PASS active OFD ordering")
            return
        if args.case == "rpc":
            check("filesystem RPC ownership", root + "/libmagicdesk_guest_test_rpc.so "
                  + root + "/model-rpc", "PASS filesystem service fixture")
            return
        if args.case == "fs-dispatch":
            result["experiment"] = {"productionAdapter": False, "productionFilesystemWorker": True,
                                    "sharedRequestBuffers": True, "execBootstrap": "ADDFD_SEND"}
            check("shared request buffer ownership", root + "/libmagicdesk_guest_test_interception_buffers.so",
                  "PASS shared request buffer ownership")
            value = check("filesystem worker descriptor transport", root + "/libmagicdesk_guest_fs_dispatch.so "
                          + root + "/dispatch", "PASS filesystem worker descriptor transport experiment")
            cases = [line for line in value["output"].splitlines()
                     if line.startswith("PASS filesystem worker O_PATH ")]
            result["experiment"]["cases"] = len(cases)
            result["experiment"]["execCases"] = sum(" exec=1 " in line for line in cases)
            result["experiment"]["sharedFilesCases"] = sum(" sharedFiles=1 " in line for line in cases)
            return
        if args.case == "fd-lifecycle":
            result["experiment"] = {"productionAdapter": False}
            value = check("native private-FD lifecycle", root + "/libmagicdesk_guest_fd_lifecycle.so "
                          + root + "/lifecycle", "PASS native private-FD lifecycle experiment")
            result["experiment"]["limitations"] = [line.removeprefix("LIMIT ")
                for line in value["output"].splitlines() if line.startswith("LIMIT ")]
            return
        if args.case == "fd-messages":
            result["experiment"] = {"productionAdapter": False, "adoptionBlocked": True,
                                    "runtimeMessageOwner": True}
            value = check("message-bound descriptor origins", root + "/libmagicdesk_guest_fd_handoff.so "
                          + root + "/messages --origin-messages", "PASS message-origin association experiment")
            result["experiment"]["limitations"] = [line.removeprefix("LIMIT ") for line in value["output"].splitlines()
                                                     if line.startswith("LIMIT ")]
            result["experiment"]["observations"] = [line for line in value["output"].splitlines() if line.startswith("OBS ")]
            result["experiment"]["unavailable"] = [line.removeprefix("UNAVAILABLE ") for line in value["output"].splitlines()
                                                    if line.startswith("UNAVAILABLE ")]
            result["experiment"]["unobserved"] = [line.removeprefix("UNOBSERVED ") for line in value["output"].splitlines()
                                                   if line.startswith("UNOBSERVED ")]
            return
        if args.case == "fd-parcel":
            result["experiment"] = {"productionAdapter": False, "adoptionBlocked": True}
            value = check("native kernel-parcel experiment", root + "/libmagicdesk_guest_fd_handoff.so "
                          + root + "/parcel --kernel-parcel", "PASS native kernel-parcel experiment")
            result["experiment"].update({
                "limitations": [line.removeprefix("LIMIT ") for line in value["output"].splitlines()
                                if line.startswith("LIMIT ")],
                "unobserved": [line.removeprefix("UNOBSERVED ") for line in value["output"].splitlines()
                               if line.startswith("UNOBSERVED ")]})
            return
        if args.case in ("proc-custody", "exec-custody", "fd-custody", "fd-custody-dirfd", "fd-custody-nofollow", "fs-buffer", "fs-results", "fs-export", "fs-return", "fs-directory", "fs-capture"):
            check("fixture directories", "mkdir -p " + root + "/native " + root + "/source/tmp "
                  + root + "/source/bin " + root + "/source/attached")
            check("stage guest image", "cp " + root + "/libmagicdesk_guest_resource_guest.so " + root + "/source/bin/test")
            check("import fixture", root + "/libmagicdesk_guest_service.so --import " + root + "/source " + root + "/store")
            if args.case == "proc-custody":
                check_proc_custody()
                return
            if args.case == "exec-custody":
                check_exec_custody()
                return
            if args.case == "fs-capture":
                check_captures()
                return
            if args.case == "fs-buffer":
                check_buffers()
                return
            if args.case == "fs-results":
                check_buffer_descriptors()
                return
            if args.case == "fs-export":
                check_exports()
                return
            if args.case == "fs-return":
                check_returns()
                return
            if args.case == "fs-directory":
                check_directories()
                return
            custody = args.case.removeprefix("fd-")
            native_custody = custody.replace("custody", "custody-native", 1)
            check("native terminal custody", root + "/libmagicdesk_guest_resource_guest.so " + native_custody + " " + root + "/native",
                  "PASS terminal RPC custody")
            check("guest terminal RPC custody", root + "/libmagicdesk_guest_run.so --store " + root
                  + "/store --deadline-seconds 60 -- /bin/test "
                  + custody + " /tmp", "PASS terminal RPC custody")
            return
        if args.case == "mapping-task":
            check("native private mapping task", root + "/libmagicdesk_guest_mapping_task.so",
                  "PASS private mapping task kernel feasibility")
            return
        if args.case == "all":
            check("resource ownership model", root + "/libmagicdesk_guest_test_task_resources.so")
        check("native descriptor publication", root + "/libmagicdesk_guest_fd_handoff.so " + root + "/handoff",
              "PASS native FD publication boundaries")
        if args.case == "fd-handoff":
            return
        for name in ("inodes", "mounts", "credentials", "rpc", "snapshot"):
            check("filesystem model " + name, root + "/libmagicdesk_guest_test_" + name + ".so "
                  + root + "/model-" + name)
        check("fixture directories", "mkdir -p " + root + "/native " + root + "/source/tmp "
              + root + "/source/bin " + root + "/source/attached")
        check("stage guest image", "cp " + root + "/libmagicdesk_guest_resource_guest.so " + root + "/source/bin/test")
        check("stage root fixture", "cp " + root + "/libmagicdesk_guest_root_guest.so " + root + "/source/bin/root-test")
        check("import fixture", root + "/libmagicdesk_guest_service.so --import " + root + "/source " + root + "/store")
        check_kernel_workflows()
        check_buffers()
        check("native kernel namespace capabilities", root + "/libmagicdesk_guest_resource_guest.so probe " + root + "/native")
        check("native resource semantics", root + "/libmagicdesk_guest_resource_guest.so native " + root + "/native",
              "PASS process resources")
        runner = root + "/libmagicdesk_guest_run.so --store " + root + "/store --deadline-seconds 60 -- "
        for protected in (False, True):
            check("initial cwd and proc origins" + (" protected" if protected else ""),
                          root + "/libmagicdesk_guest_run.so --diagnostics --cwd /tmp --store "
                          + root + "/store --deadline-seconds 60 -- /bin/test "
                          + ("origins-protected" if protected else "origins") + " /tmp",
                          "PASS initial cwd and proc aliases",
                          patterns=(r"PROBE image-cwd pid=\d+ known=1",),
                          absent_patterns=(r"PROBE path-capture pid=\d+ base=\d+",))
            check("RPC cwd without private capture" + (" protected" if protected else ""),
                  runner + "/bin/test " + ("rpc-cwd-protected" if protected else "rpc-cwd")
                  + " /tmp", "PASS RPC cwd without guest directory capture")
        check("guest resource semantics", runner + shlex.join(["/bin/test", "guest", "/tmp"]), "PASS process resources")
        check("guest namespace capabilities", runner + "/bin/test probe /tmp")
        check("guest roots", root + "/libmagicdesk_guest_run.so --user 0:0 --store "
              + root + "/store --deadline-seconds 60 -- /bin/root-test run", "PASS guest roots")
        check("native root directory", "mkdir -m 700 " + root + "/attached")
        check("guest native roots", root + "/libmagicdesk_guest_run.so --user 0:0 --store "
              + root + "/store --bind " + root + "/attached /jail --deadline-seconds 60"
              + " -- /bin/root-test attached", "PASS guest roots")
        if args.compare_installed:
            result["comparison"] = {}
            candidates = {"installed": "magicdesk-guest", "candidate": root + "/libmagicdesk_guest_run.so"}
            for workload in ("metadata", "spawn"):
                samples = {name: [] for name in candidates}
                counters = {}
                for turn in range(4):
                    order = list(candidates) if turn % 2 == 0 else list(reversed(candidates))
                    for name in order:
                        value = check(f"{workload} {name} round {turn}", candidates[name]
                                      + " --store " + root + "/store --deadline-seconds 60 -- /bin/test "
                                      + workload + " /tmp", "PASS workload=" + workload)
                        elapsed = int(re.search(r"elapsedNs=(\d+)", value["output"])[1])
                        if turn:
                            samples[name].append(elapsed)
                for name, binary in candidates.items():
                    value = check(f"{workload} {name} counters", binary
                                  + " --statistics --store " + root + "/store --deadline-seconds 60 -- /bin/test "
                                  + workload + " /tmp", "PASS workload=" + workload)
                    counters[name] = [line for line in value["output"].splitlines() if line.startswith("MD_")]
                result["comparison"][workload] = {"elapsedNs": samples, "counters": counters,
                    "medianNs": {name: statistics.median(values) for name, values in samples.items()}}
                def operations(lines):
                    return [re.sub(r"\s+(?:\w*Ns|ns)=\d+", "", line) for line in lines
                            if not line.startswith(("MD_CPU ", "MD_BROKER synchronousWake="))]
                result["comparison"][workload]["sameOperationCounts"] = (
                    operations(counters["installed"]) == operations(counters["candidate"]))
    finally:
        try:
            if not args.keep:
                check("remove owned fixtures", "rm -rf " + root)
        finally:
            try:
                client.call("console.close", {"sessionId": session})
            finally:
                name = "resource-results.json" if args.case == "all" else "resource-" + args.case + "-results.json"
                (args.build / name).write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
