"""For each Prowler check of a cloud, the service modules whose clients it imports, followed through
helper imports. Reads Prowler's source as text. Prints JSON {check: [service, ...]}.

Usage: python3 -I scripts/prowler-check-reads.py <prowler package dir> <aws|azure> <checks file>

<prowler package dir> is the `prowler` directory of a clone of prowler-cloud/prowler at the release's
tag, or of an installed package. Nothing in it is run, so the release need not be installed.

<checks file> is the framework's compliance file in that directory,
prowler/compliance/<cloud>/<framework>.json, whose requirements' checks are what
`prowler <cloud> --list-checks-json --compliance <framework>` lists; or a check list, one per line or
space-separated. The output is awsCheckReads in internal/scanners/prowler_aws_reads.go and
azureCheckReads in internal/scanners/prowler_azure_reads.go.
"""
import json, os, re, sys

root, cloud, checks_file = sys.argv[1], sys.argv[2], sys.argv[3]


def framework_checks(path):
    if path.endswith(".json"):
        with open(path) as f:
            return sorted({c for r in json.load(f)["Requirements"] for c in r.get("Checks", [])})
    with open(path) as f:
        return f.read().split()


svc_dir = os.path.join(root, "providers", cloud, "services")
imp_re = re.compile(r"from prowler\.providers\." + cloud + r"\.services\.([a-z0-9_.]+) import")


def path_of(mod):
    p = os.path.join(svc_dir, *mod.split(".")) + ".py"
    return p if os.path.exists(p) else None


def find_check(check):
    for svc in sorted(os.listdir(svc_dir)):
        if os.path.exists(os.path.join(svc_dir, svc, check, check + ".py")):
            return f"{svc}.{check}.{check}"
    return None


def services(mod, seen):
    if mod in seen:
        return set()
    seen.add(mod)
    p = path_of(mod)
    if p is None:
        return set()
    out = set()
    for m in imp_re.findall(open(p).read()):
        if m.endswith("_client"):
            out.add(m.split(".")[0])
        else:
            out |= services(m, seen)
    return out


result = {}
for check in framework_checks(checks_file):
    mod = find_check(check)
    result[check] = sorted(services(mod, set())) if mod else None
json.dump(result, sys.stdout, indent=1, sort_keys=True)
