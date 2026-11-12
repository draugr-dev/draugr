"""For each Prowler check of a cloud, the service modules whose clients it imports, followed through
helper imports. Reads Prowler's source as text. Prints JSON {check: [service, ...]}.

Usage: python3 -I scripts/prowler-check-reads.py <prowler package dir> <aws|azure> <checks file>

<checks file> is the framework's check list, one per line or space-separated, as
`prowler <cloud> --list-checks-json --compliance <framework>` lists them under the cloud's name. The
output is awsCheckReads in internal/scanners/prowler_aws_reads.go and azureCheckReads in
internal/scanners/prowler_azure_reads.go.
"""
import json, os, re, sys

root, cloud, checks_file = sys.argv[1], sys.argv[2], sys.argv[3]
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
for check in open(checks_file).read().split():
    mod = find_check(check)
    result[check] = sorted(services(mod, set())) if mod else None
json.dump(result, sys.stdout, indent=1, sort_keys=True)
