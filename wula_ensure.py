#!/usr/bin/env python3
"""ARM account refill helper. Writes only wula_bank.json on a supplied private branch."""
import argparse
import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PRIVATE_REPO = "qiufeng668/polymerization-1"


def api_session():
    import requests
    token = os.environ.get("GIT_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GIT_TOKEN missing")
    s = requests.Session()
    s.headers.update({"Authorization": "Bearer " + token,
                      "Accept": "application/vnd.github+json",
                      "X-GitHub-Api-Version": "2022-11-28"})
    return s


def load_rows(path):
    try:
        rows = json.loads(path.read_text())
        return rows if isinstance(rows, list) else []
    except (OSError, ValueError):
        return []


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target-branch", required=True)
    a = p.parse_args()
    vault = ROOT / "vault_repo"
    vault.mkdir(exist_ok=True)
    bank = vault / "wula_bank.json"
    rows = load_rows(bank)

    # Reuse a confirmed active account. A stale subscription response alone is not proof.
    sys.path.insert(0, str(ROOT / "plugins"))
    import wula
    wula.PROXY = None
    wula._DEADLINE = time.monotonic() + 210
    usable = False
    for entry in rows[:3]:
        ok, reason = wula._bank_account_usable(entry)
        print("BANK_CHECK", "active" if ok else reason, flush=True)
        if ok:
            hit = wula._use_bank()
            if hit:
                print("REFILL_SKIP active_account=1", flush=True)
                return 0

    print("REFILL_START registering_one=1", flush=True)
    env = os.environ.copy()
    env["WULA_FORCE_REGISTER"] = "1"
    env["WULA_BUDGET_SECONDS"] = "210"
    env["WULA_MAX_ATTEMPTS"] = "1"
    result = subprocess.run([sys.executable, str(ROOT / "plugins/wula.py"),
                             "--outdir", "/tmp/wula-arm-output"],
                            cwd=ROOT, env=env, timeout=230)
    if result.returncode:
        raise RuntimeError("Wula registration failed, exit=%d" % result.returncode)

    out = Path("/tmp/wula-arm-output")
    nodes = out / "nodes.txt"
    accounts = out / "accounts.json"
    assert nodes.exists() and any(x.strip() for x in nodes.read_text().splitlines()), "empty node output"
    created = [x for x in json.loads(accounts.read_text()) if x.get("token") and not x.get("bank_fallback")]
    assert len(created) == 1, "expected exactly one newly registered account"
    rows = load_rows(bank)
    rows = [created[0]] + [x for x in rows if x.get("token") != created[0]["token"]]
    rows = rows[:10]
    bank.write_text(json.dumps(rows, ensure_ascii=False, indent=1))
    print("REFILL_VERIFIED registered=1 nodes=%d" % sum(bool(x.strip()) for x in nodes.read_text().splitlines()), flush=True)

    s = api_session()
    base = "https://api.github.com/repos/" + PRIVATE_REPO
    ref = s.get(base + "/git/ref/heads/" + a.target_branch, timeout=(5, 18))
    if ref.status_code == 404:
        main = s.get(base + "/git/ref/heads/main", timeout=(5, 18)); main.raise_for_status()
        create = s.post(base + "/git/refs", json={"ref": "refs/heads/" + a.target_branch,
                                                  "sha": main.json()["object"]["sha"]}, timeout=(5, 18))
        create.raise_for_status()
        ref = s.get(base + "/git/ref/heads/" + a.target_branch, timeout=(5, 18))
    ref.raise_for_status()
    current_sha = ref.json()["object"]["sha"]
    file_url = base + "/contents/wula_bank.json"
    remote = s.get(file_url, params={"ref": a.target_branch}, timeout=(5, 18)); remote.raise_for_status()
    remote_json = remote.json()
    payload = {"message": "Validate ARM Wula refill handoff",
               "content": base64.b64encode(bank.read_bytes()).decode(),
               "sha": remote_json["sha"], "branch": a.target_branch}
    update = s.put(file_url, json=payload, timeout=(5, 22))
    update.raise_for_status()
    print("REFILL_PUSHED branch=%s" % a.target_branch, flush=True)

    verify = s.get(file_url, params={"ref": a.target_branch}, timeout=(5, 18)); verify.raise_for_status()
    checked = json.loads(base64.b64decode(verify.json()["content"]))
    assert checked[0].get("token") == created[0]["token"], "fresh account absent on target branch"
    print("REFILL_REMOTE_VERIFIED entries=%d" % len(checked), flush=True)


if __name__ == "__main__":
    main()
