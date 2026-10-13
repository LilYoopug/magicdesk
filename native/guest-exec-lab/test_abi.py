#!/usr/bin/env python3
"""Install and run ABI fixtures in an explicitly selected disposable guest store."""
import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import tarfile
import tomllib
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--libc-build", type=Path, required=True)
    parser.add_argument("--static-build", type=Path, required=True)
    parser.add_argument("--libc", choices=["glibc", "musl"], required=True)
    parser.add_argument("--store", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--user", default="2000:2000", help="Logical guest account for ABI execution")
    args = parser.parse_args()
    try:
        fixture_uid, fixture_gid = map(int, args.user.split(":"))
    except ValueError:
        parser.error("--user requires numeric UID:GID")
    repo = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("transport", repo / "scripts/mcp-client.py")
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    config = tomllib.loads((Path.home() / ".codex/config.toml").read_text())["mcp_servers"]["magicdesk"]
    client = transport.Client(config["url"], config["http_headers"]["Authorization"].removeprefix("Bearer "))
    state = client.call("get_state")
    assert state["shell"]["uid"] == 2000
    tag = uuid.uuid4().hex
    directory = "/data/local/tmp/md-guest-abi-" + tag
    files = [args.libc_build / ("md-" + name + "-fixture") for name in ["exec", "execfd", "process_image", "arguments", "ipc"]]
    files += [args.static_build / ("md-static-" + name) for name in ["exec", "pie", "exec-2m", "pie-2m"]]
    files += [args.build / "md-freestanding-fixture"]
    archive = args.build / ("abi-" + args.libc + "-" + tag + ".tar")
    def fixture_metadata(info):
        info.uid, info.gid = fixture_uid, fixture_gid
        info.uname = info.gname = ""
        info.mode = 0o755 if info.name.startswith("usr/bin/") else 0o644
        return info

    with tarfile.open(archive, "w") as output:
        for path in files:
            output.add(path, arcname="usr/bin/" + path.name, recursive=False, filter=fixture_metadata)
        output.add(Path(__file__).with_name("fixtures") / "md-guest-fixture",
                   arcname="etc/md-guest-fixture", recursive=False, filter=fixture_metadata)
    result = {"id": tag, "libc": args.libc, "store": args.store,
              "runtime": args.runtime, "user": args.user, "hostUid": state["shell"]["uid"],
              "app": state["app"], "checks": [], "passed": False}
    console = client.call("console.open", {"directory": "/data/local/tmp"})["sessionId"]

    def command(value):
        response = client.call("console.execute", {"sessionId": console, "command": value})
        assert response["exitCode"] == 0, response
        return response["output"]

    runner = shlex.join([args.runtime + "/libmagicdesk_guest_run.so", "--store", args.store,
                        "--user", args.user, "--"])
    installer = shlex.join([args.runtime + "/libmagicdesk_guest_run.so", "--store", args.store,
                           "--user", "0:0", "--"])
    try:
        command("mkdir " + shlex.quote(directory))
        result["bundle"] = transport.upload(client, str(archive), directory + "/fixtures.tar")
        result["runtimeHashes"] = command("sha256sum " + shlex.join(
            [args.runtime + "/libmagicdesk_guest_" + name + ".so" for name in ["run", "supervisor", "bootstrap", "service"]]))
        command("cat " + shlex.quote(directory + "/fixtures.tar") + " | " + installer + " /bin/tar -xf - -C /")
        for path in files:
            # EVENT_WAIT: console command completion; timeout terminates a hung fixture tree.
            arguments = ["/usr/bin/" + path.name]
            if path.name == "md-ipc-fixture": arguments += ["local", "/tmp/md-ipc-" + tag]
            value = command("timeout 60 " + runner + " " + shlex.join(arguments))
            result["checks"].append({"fixture": path.name, "output": value})
            print(args.libc, path.name, value.strip(), flush=True)
        result["passed"] = True
    except Exception as error:
        result["failure"] = str(error)
        raise
    finally:
        client.call("console.close", {"sessionId": console})
        (args.build / (args.libc + "-abi-results.json")).write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
