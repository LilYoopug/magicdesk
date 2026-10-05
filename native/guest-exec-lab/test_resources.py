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
    parser.add_argument("--compare-installed", action="store_true",
                        help="Compare identical metadata/spawn fixtures with the installed runtime")
    args = parser.parse_args()
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
    result = {"device": state["device"], "app": state["app"], "root": root, "checks": []}

    def check(name, command, contains=None):
        value = client.call("console.execute", {"sessionId": session, "command": command})
        passed = value["exitCode"] == 0 and (contains is None or contains in value["output"])
        result["checks"].append({"name": name, "passed": passed, **value})
        print(("PASS " if passed else "FAIL ") + name + "\n" + value["output"], flush=True)
        if not passed:
            raise RuntimeError(name)
        return value

    try:
        check("isolated staging", "mkdir -m 700 " + root)
        for name in ("bootstrap", "supervisor", "run", "service", "resource_guest"):
            file = "libmagicdesk_guest_" + name + ".so"
            transport.upload(client, args.build / file, root + "/" + file)
        check("prepare fixtures", "chmod 700 " + root + "/*.so")
        check("fixture directories", "mkdir -p " + root + "/native " + root + "/source/tmp "
              + root + "/source/bin")
        check("stage guest image", "cp " + root + "/libmagicdesk_guest_resource_guest.so " + root + "/source/bin/test")
        check("import fixture", root + "/libmagicdesk_guest_service.so --import " + root + "/source " + root + "/store")
        check("native kernel namespace capabilities", root + "/libmagicdesk_guest_resource_guest.so probe " + root + "/native")
        check("native resource semantics", root + "/libmagicdesk_guest_resource_guest.so native " + root + "/native",
              "PASS process resources")
        runner = root + "/libmagicdesk_guest_run.so --store " + root + "/store --deadline-seconds 60 -- "
        check("guest resource semantics", runner + shlex.join(["/bin/test", "guest", "/tmp"]), "PASS process resources")
        check("guest namespace capabilities", runner + "/bin/test probe /tmp")
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
            client.call("console.close", {"sessionId": session})
            (args.build / "resource-results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
