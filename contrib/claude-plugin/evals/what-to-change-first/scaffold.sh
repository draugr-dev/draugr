#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo

# Enough findings, of enough kinds, that the answer is a matter of grouping rather than reading.
# With a handful, a reply can count them off the SARIF by hand and never needs fix_list, which is
# the tool this case is about; at this size the SARIF runs past what one read returns. Each kind
# has its own count, so "what clears the most" has one answer: fourteen GitHub tokens, then eleven
# private keys, then nine AWS keys.
rand() { LC_ALL=C tr -dc "$1" </dev/urandom | head -c "$2" || true; }

# repo committed two AWS keys; seven more make nine.
for i in 1 2 3 4 5 6 7; do
  svc=$([ $((i % 2)) -eq 0 ] && echo web || echo api)
  aws_key "services/$svc/deploy/aws.$i.env"
done

for i in $(seq 1 14); do
  svc=$([ $((i % 2)) -eq 0 ] && echo web || echo api)
  mkdir -p "services/$svc/ci"
  printf 'GITHUB_TOKEN=ghp_%s\n' "$(rand 'A-Za-z0-9' 36)" >"services/$svc/ci/token.$i.env"
done

# The armor is assembled here rather than written out, so this script is not itself a private key
# to a secret scanner reading the repository it lives in.
armor="RSA PRIVATE KEY"
for i in $(seq 1 11); do
  svc=$([ $((i % 2)) -eq 0 ] && echo web || echo api)
  {
    echo "-----BEGIN $armor-----"
    for _ in 1 2 3 4 5 6 7 8; do rand 'A-Za-z0-9+/' 64; echo; done
    echo "-----END $armor-----"
  } >"services/$svc/deploy/key.$i.pem"
done

# One eval per file, each its own thing to change.
for svc in api web; do
  for i in $(seq 1 20); do
    printf 'export function load%s(input) {\n  return eval(input);\n}\n' "$i" >"services/$svc/src/load$i.js"
  done
done

git_ add -A
git_ commit -q -m "Add the deploy credentials and the plugin loaders"
descriptor
report .
# Only the SARIF, as a pipeline that ran the scan elsewhere hands it over. report.json carries the
# actions already grouped, and a reply read from it answers without the tool this case is about.
rm report.json
