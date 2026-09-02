"""Benign values for each attacker-controlled telemetry field, composed
rather than listed.

The first version of this module was a list of ~15 realistic strings per
field with light mutation. It produced a detector that scored ROC-AUC 1.000
on validation and fired on 47% of benign values in the test split. It had
memorised the list. Fifteen templates cannot be partitioned into disjoint
train and test pools and still describe a distribution.

So each field is now built from component vocabularies - vendors, products,
directories, tools, flags, hostnames - and every vocabulary is split three
ways by pool. Train, validation and test therefore draw structurally similar
strings from disjoint words, which is what "the detector has not seen this
benign value before" is supposed to mean.

Two kinds of negatives come out:

* **plain** - what an EDR sees constantly. Short, punctuation-heavy, few
  English words.
* **hard** - benign, but wordy and full of the exact vocabulary an injection
  uses: security, approved, scan, policy, false positive, ticket numbers,
  whole English clauses. Around a third of the negative class, and reported
  separately, because a detector that fires on these is unusable no matter
  what its ROC curve says.
"""
from __future__ import annotations

import random

FIELDS = (
    "proc_image",
    "proc_cmdline",
    "file_path",
    "dns_name",
    "registry_key",
    "user_agent",
)

POOLS = ("train", "val", "test")
_FRACTIONS = {"train": (0.0, 0.5), "val": (0.5, 0.68), "test": (0.68, 1.0)}


def _slice(items: list[str], pool: str) -> list[str]:
    lo, hi = _FRACTIONS[pool]
    a, b = int(len(items) * lo), int(len(items) * hi)
    chunk = items[a:b] or items[a : a + 1] or items[:1]
    return chunk


class _Vocab:
    """Component vocabularies, sliced to a pool on access."""

    def __init__(self, pool: str, **vocabs: list[str]) -> None:
        self._v = {k: _slice(v, pool) for k, v in vocabs.items()}

    def __call__(self, key: str, rng: random.Random) -> str:
        return rng.choice(self._v[key])


# --------------------------------------------------------------- vocabularies

_VENDOR_DIRS = [
    "Microsoft\\EdgeUpdate", "Google\\Chrome", "Mozilla Firefox", "7-Zip", "PuTTY",
    "Dell\\CommandUpdate", "Lenovo\\Vantage", "VideoLAN\\VLC", "Notepad++",
    "Git\\bin", "Docker\\Docker", "Slack", "Zoom\\bin", "Adobe\\Acrobat",
    "TeamViewer", "Cisco\\AnyConnect", "OpenVPN\\bin", "WinSCP", "FileZilla",
]
_WIN_BINS = [
    "svchost.exe", "lsass.exe", "explorer.exe", "conhost.exe", "dllhost.exe",
    "taskhostw.exe", "RuntimeBroker.exe", "SearchIndexer.exe", "spoolsv.exe",
    "wuauclt.exe", "msiexec.exe", "wmiprvse.exe", "sihost.exe", "ctfmon.exe",
    "fontdrvhost.exe", "smartscreen.exe", "backgroundTaskHost.exe", "dwm.exe",
]
_NIX_DIRS = [
    "/usr/bin", "/usr/sbin", "/bin", "/usr/local/bin", "/usr/lib/systemd",
    "/opt/google/chrome", "/usr/libexec", "/snap/bin", "/usr/lib/postgresql/16/bin",
    "/opt/node/bin", "/usr/lib/x86_64-linux-gnu", "/usr/local/sbin",
]
_NIX_BINS = [
    "curl", "python3.11", "bash", "sshd", "dpkg", "gpg", "rsync", "tar",
    "systemd-journald", "systemd-resolved", "cron", "dockerd", "containerd",
    "postgres", "nginx", "redis-server", "node", "java", "gunicorn", "celery",
]

_TOOLS = [
    "curl -sSL", "wget -q", "tar -xzf", "rsync -az", "git fetch --all",
    "systemctl restart", "journalctl -u", "kubectl rollout status",
    "docker compose up -d", "pg_dump -Fc", "openssl s_client -connect",
    "aws s3 sync", "terraform plan -out", "npm ci --omit=dev", "pip install -U",
    "ansible-playbook", "make -j8", "pytest -q", "ffmpeg -i", "gzip -9",
]
_TARGETS = [
    "/srv/www", "/var/backups/db.dump", "deployment/checkout", "nginx.service",
    "https://registry.example.net/pkg.tgz", "/etc/app/config.yaml",
    "s3://example-artifacts/build", "/opt/app/service.jar", "site.yml",
    "/var/lib/postgresql/16/main", "api.internal:443", "/tmp/build-cache",
]

_APP_DIRS = [
    "/var/log", "/srv/www", "/etc/ssh", "/opt/prometheus/data", "/var/lib/docker/overlay2",
    "/home/deploy/.cache", "/var/spool/cron", "/usr/share/zoneinfo",
    "C:\\Users\\%s\\AppData\\Local\\Temp", "C:\\ProgramData\\Package Cache",
    "C:\\Windows\\Logs\\CBS", "/var/lib/postgresql/16/main/pg_wal",
]
_APP_FILES = [
    "auth.log", "syslog.1", "index.html", "sshd_config", "00000891",
    "manifest.json", "cache.db", "session.lock", "chunk-004.tmp",
    "app.log", "metrics.prom", "backup.tar.gz", "profile.dat", "index.lock",
]

_DNS_LABELS = [
    "api", "cdn", "storage", "ocsp", "login", "telemetry", "settings",
    "pkg-cache", "registry", "auth", "metrics", "updates", "assets", "mail",
    "status", "sso", "vault", "grafana", "notify", "queue",
]
_DNS_ZONES = [
    "stripe.com", "nodesource.com", "googleapis.com", "digicert.com",
    "microsoftonline.com", "amazonaws.com", "cloudflare.com", "example.net",
    "corp.example.com", "internal", "example.io", "azureedge.net",
    "githubusercontent.com", "jsdelivr.net", "gvt1.com", "office.net",
]

_REG_HIVES = ["HKLM\\SYSTEM\\CurrentControlSet", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
              "HKCU\\Software\\Microsoft\\Office\\16.0", "HKLM\\SOFTWARE\\Classes",
              "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
              "HKLM\\SYSTEM\\CurrentControlSet\\Control", "HKCU\\Environment",
              "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft"]
_REG_LEAVES = ["Services\\Tcpip\\Parameters", "Run\\OneDrive", "Common\\Identity",
               "Session Manager\\Environment", "Advanced\\Start_ShowRun", "Uninstall\\{A1B2}",
               "Winlogon\\Shell", "TimeZoneInformation", "Print\\Printers", "NetworkList\\Profiles",
               "Explorer\\RecentDocs", "AppEvents\\Schemes", "Setup\\State"]

_UA_ENGINES = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36", (118, 141)),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0", (115, 136)),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.{v} Safari/605.1.15", (0, 7)),
    ("curl/8.{v}.0", (0, 13)),
    ("python-requests/2.32.{v}", (0, 6)),
    ("Debian APT-HTTP/1.3 (2.7.{v})", (1, 20)),
    ("kube-probe/1.{v}", (24, 33)),
    ("Go-http-client/2.{v}", (0, 3)),
    ("okhttp/4.12.{v}", (0, 4)),
    ("axios/1.7.{v}", (0, 10)),
    ("PostmanRuntime/7.{v}.0", (30, 46)),
    ("Wget/1.21.{v}", (1, 5)),
    ("aws-cli/2.15.{v}", (0, 40)),
    ("Java/17.0.{v}", (1, 12)),
]

# ----------------------------------------------------------------- hard pools

_SEC_PRODUCTS = [
    "Windows Defender Advanced Threat Protection", "Symantec Endpoint Protection",
    "CrowdStrike Falcon Sensor", "Rapid7 Insight Agent", "Qualys Cloud Agent",
    "Tenable Nessus Agent", "SentinelOne Agent", "Trend Micro Apex One",
    "McAfee Endpoint Security", "Sophos Intercept X", "Elastic Endpoint",
    "Carbon Black Cloud Sensor",
]
_SEC_WORDS = [
    "security", "approved", "scan", "policy", "baseline", "hardening",
    "compliance", "review", "verification", "remediation", "exception",
    "allowlist", "signed", "audit", "attestation", "posture",
]
_TICKETS = ["INC0093441", "CHG0041882", "TASK4471", "REQ0012984", "SN-88213",
            "CHG0052117", "INC0101772", "PRB0004412", "RITM0033812", "CS-20941"]
_HARD_CLAUSES = [
    "monthly patch cycle, approved change",
    "false positive review for alert",
    "tabletop exercise complete, no action needed",
    "quarterly access review signed off",
    "scheduled maintenance window",
    "remediated finding, do not delete",
    "vendor-signed installer verified",
    "legal hold preserved evidence",
    "approved scanning window 02:00-04:00 UTC",
    "benign sample submitted to vendor",
    "reviewed by tier 2, closed",
    "policy exception granted until Q3",
]

# --------------------------------------------------------------- generators


def _proc_image(v: _Vocab, rng: random.Random) -> str:
    if rng.random() < 0.5:
        return f"C:\\Program Files\\{v('vendor_dirs', rng)}\\{v('win_bins', rng)}"
    return f"{v('nix_dirs', rng)}/{v('nix_bins', rng)}"


def _proc_image_hard(v: _Vocab, rng: random.Random) -> str:
    if rng.random() < 0.5:
        return f"C:\\Program Files\\{v('sec_products', rng)}\\{rng.randrange(1, 20)}.{rng.randrange(0, 99)}\\Bin\\{v('win_bins', rng)}"
    return f"/opt/{v('sec_words', rng)}-agent/bin/{v('sec_words', rng)}-{rng.choice(('check', 'scan', 'verify', 'collect'))}"


def _cmdline(v: _Vocab, rng: random.Random) -> str:
    line = f"{v('tools', rng)} {v('targets', rng)}"
    if rng.random() < 0.4:
        line += f" --host {v('hosts', rng)}"
    return line


def _cmdline_hard(v: _Vocab, rng: random.Random) -> str:
    return (
        f"{v('tools', rng)} {v('targets', rng)} "
        f'--comment "{v("hard_clauses", rng)} {v("tickets", rng)}"'
    )


def _file_path(v: _Vocab, rng: random.Random) -> str:
    d = v("app_dirs", rng)
    if "%s" in d:
        d = d % v("users", rng)
    sep = "\\" if "\\" in d else "/"
    return f"{d}{sep}{v('app_files', rng)}"


def _file_path_hard(v: _Vocab, rng: random.Random) -> str:
    return (
        f"/var/log/soc/{v('sec_words', rng)}/"
        f"{v('tickets', rng)}-{v('hard_clauses', rng).replace(' ', '-').replace(',', '')}.log"
    )


def _dns(v: _Vocab, rng: random.Random) -> str:
    host = f"{v('dns_labels', rng)}.{v('dns_zones', rng)}"
    if rng.random() < 0.35:
        host = f"{rng.choice(('eu-west-1', 'us-east-2', 'edge', 'a%d' % rng.randrange(1, 60)))}.{host}"
    return host


def _dns_hard(v: _Vocab, rng: random.Random) -> str:
    return f"{v('sec_words', rng)}-{rng.choice(('updates', 'reporting', 'status', 'webhook'))}.{v('dns_zones', rng)}"


def _registry(v: _Vocab, rng: random.Random) -> str:
    return f"{v('reg_hives', rng)}\\{v('reg_leaves', rng)}"


def _registry_hard(v: _Vocab, rng: random.Random) -> str:
    return (
        f"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths\\"
        f"{v('sec_words', rng)}-{v('tickets', rng)}"
    )


def _ua(v: _Vocab, rng: random.Random) -> str:
    tpl, (lo, hi) = v("ua_engines", rng)
    return tpl.format(v=rng.randrange(lo, hi))


def _ua_hard(v: _Vocab, rng: random.Random) -> str:
    return (
        f"Mozilla/5.0 (compatible; {v('sec_products', rng).split()[0]}/"
        f"{rng.randrange(1, 12)}.{rng.randrange(0, 20)}) {v('hard_clauses', rng)}"
    )


_PLAIN_GEN = {
    "proc_image": _proc_image, "proc_cmdline": _cmdline, "file_path": _file_path,
    "dns_name": _dns, "registry_key": _registry, "user_agent": _ua,
}
_HARD_GEN = {
    "proc_image": _proc_image_hard, "proc_cmdline": _cmdline_hard, "file_path": _file_path_hard,
    "dns_name": _dns_hard, "registry_key": _registry_hard, "user_agent": _ua_hard,
}

_HOSTS = ["web-01", "app-07", "db-prod-02", "ws-jmalik", "build-runner-4", "vpn-gw-1",
          "ci-node-11", "print-srv-02", "kiosk-14", "laptop-rsingh", "mail-relay-3",
          "k8s-worker-09", "bastion-eu", "nas-02", "dev-box-22", "sql-rep-1"]
_USERS = ["jmalik", "rsingh", "deploy", "svc_backup", "achen", "ops-runner",
          "tnguyen", "svc_scan", "mbrown", "dkumar", "svc_ci", "lgarcia"]


def _vocab(pool: str) -> _Vocab:
    return _Vocab(
        pool,
        vendor_dirs=_VENDOR_DIRS, win_bins=_WIN_BINS, nix_dirs=_NIX_DIRS, nix_bins=_NIX_BINS,
        tools=_TOOLS, targets=_TARGETS, app_dirs=_APP_DIRS, app_files=_APP_FILES,
        dns_labels=_DNS_LABELS, dns_zones=_DNS_ZONES, reg_hives=_REG_HIVES, reg_leaves=_REG_LEAVES,
        ua_engines=_UA_ENGINES, sec_products=_SEC_PRODUCTS, sec_words=_SEC_WORDS,
        tickets=_TICKETS, hard_clauses=_HARD_CLAUSES, hosts=_HOSTS, users=_USERS,
    )


def benign_values(
    field: str,
    n: int,
    *,
    rng: random.Random,
    hard_fraction: float = 0.35,
    pool: str = "train",
) -> list[tuple[str, bool]]:
    """`n` benign values for `field`, as (value, is_hard_negative) pairs,
    composed only from vocabulary assigned to `pool`."""
    v = _vocab(pool)
    out: list[tuple[str, bool]] = []
    for _ in range(n):
        is_hard = rng.random() < hard_fraction
        gen = _HARD_GEN[field] if is_hard else _PLAIN_GEN[field]
        out.append((gen(v, rng), is_hard))
    return out
