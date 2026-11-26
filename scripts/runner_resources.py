"""Low-rate runner diagnostics. Report counters and sanitized target basenames."""
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.request import HTTPRedirectHandler, Request, build_opener


def pairs(path):
    return {k.rstrip(":"): int(v) for k, v, *_ in
            (line.split() for line in path.read_text().splitlines())}


def build_target(pid):
    # Read only a compiler/linker argv, never log it or expand response files.
    with (pid / "cmdline").open("rb") as stream:
        args = stream.read(65536).split(b"\0")
    for arg, value in zip(args, args[1:]):
        if arg != b"-o":
            continue
        name = value.rsplit(b"/", 1)[-1]
        if re.fullmatch(rb"(?:[A-Za-z0-9_.+-]{1,120}\.(?:o|bc|ko|s)|(?:\.tmp_)?vmlinux(?:\.[A-Za-z0-9_.-]{1,48})?)", name):
            return name.decode("ascii")
    return None


def processes(proc, targets):
    result = {}
    for pid in proc.iterdir():
        if not pid.name.isdecimal():
            continue
        try:
            stat = (pid / "stat").read_text()
            name, _, fields = stat[stat.index("(") + 1:].rpartition(") ")
            kind = next((k for k in ("clang", "ld.lld", "lld", "java", "bazel",
                                      "make", "pahole", "llvm") if name.startswith(k)), None)
            if kind:
                fields = fields.split()
                counts = result.setdefault(kind, [0, 0, 0, 0])
                counts[0] += 1
                counts[1] += int(fields[11]) + int(fields[12])
                counts[2] += int(fields[21])
                counts[3] += fields[0] == "D"
                if kind in ("clang", "ld.lld", "lld"):
                    target = build_target(pid)
                    if target:
                        targets.add(("CC:" if kind == "clang" else "LD:") + target)
        except (OSError, ValueError, IndexError):
            continue
    return result  # count, live CPU ticks, RSS pages, uninterruptible count


def sample(directory, proc=Path("/proc"), cg=Path("/sys/fs/cgroup")):
    mem = pairs(proc / "meminfo")
    vm = pairs(proc / "vmstat")
    fs = os.statvfs(directory)
    targets = set()
    data = dict(unix=int(time.time()), disk_free_bytes=fs.f_bavail * fs.f_frsize,
                disk_free_inodes=fs.f_favail, proc=processes(proc, targets))
    data["targets"] = sorted(targets, key=lambda name: (not name.startswith("LD:"), name))
    data.update({k: mem[k] for k in ("MemAvailable", "SwapFree", "SwapTotal")})
    data.update({k: vm.get(k) for k in ("oom_kill", "pswpin", "pswpout")})
    for key in ("cpu", "io", "memory"):
        path = proc / "pressure" / key
        if path.exists():
            data[key + "_psi"] = path.read_text().strip()
    for line in (proc / "self/cgroup").read_text().splitlines():
        if not line.startswith("0::"):
            continue
        group = cg / line[3:].lstrip("/")
        for key in ("memory.current", "memory.max", "memory.peak",
                    "memory.swap.current", "memory.swap.max", "memory.events"):
            path = group / key
            if path.is_file():
                data[key] = pairs(path) if key == "memory.events" else path.read_text().strip()
    return data


def brief(d, first):
    def mib(k):
        return d[k] // 1024
    kill = d["oom_kill"]
    delta = kill - first["oom_kill"] if kill is not None and first["oom_kill"] is not None else "?"
    p = d["proc"]
    n = lambda k: p.get(k, [0])[0]
    return (f"availMiB={mib('MemAvailable')} swapFreeMiB={mib('SwapFree')} "
            f"diskMiB={d['disk_free_bytes'] >> 20} oomDelta={delta} "
            f"clang={n('clang')} ld={n('lld') + n('ld.lld')} make={n('make')}")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def main(directory, out):
    sha = os.environ["GITHUB_SHA"]
    assert re.fullmatch("[a-f0-9]{40}", sha)
    assert os.environ["GITHUB_REPOSITORY"].lower() == "vring99/bakasu-gki-builder"
    url = f"https://api.github.com/repos/vring99/bakasu-gki-builder/statuses/{sha}"
    token = os.environ.pop("DIAG_TOKEN")
    opener = build_opener(NoRedirect())
    first = None
    last = -100
    while not (out / "stop").exists():
        d = sample(directory)
        first = first or d
        print(json.dumps(d), flush=True)
        summary = brief(d, first)
        targets = ",".join(d["targets"]) or "not-sampled"
        with (out / "targets.log").open("a", encoding="ascii") as log:
            print(time.strftime("%H:%M:%SZ", time.gmtime()), summary, targets, file=log)
        if time.monotonic() - last >= 55:
            body = dict(state="success", context="diagnostics/resource-sample",
                        description=(summary + " " + targets)[:140])
            req = Request(url, data=json.dumps(body).encode(), headers={
                "Authorization": "Bearer " + token, "Content-Type": "application/json"})
            try:
                with opener.open(req, timeout=10) as r:
                    if r.status != 201:
                        raise ValueError("unexpected status")
                (out / "ready").touch()
                last = time.monotonic()
            except (OSError, ValueError) as exc:
                print("sample publish failed", type(exc).__name__, getattr(exc, "code", ""), file=sys.stderr)
        time.sleep(30)


if __name__ == "__main__":
    main(sys.argv[1], Path(sys.argv[2]))
