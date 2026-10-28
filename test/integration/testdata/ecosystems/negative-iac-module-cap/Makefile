# Regenerates repo/infra/main.tf, a root module calling modules/good once per round Trivy
# evaluates and then modules/bad, the one call past the last round. Trivy 0.69.3 to 0.76.1
# evaluate 32 rounds; set ROUNDS to what a later release evaluates. Needs only a shell.
ROUNDS := 32

.PHONY: repo
repo:
	{ for i in $$(seq -w 1 $(ROUNDS)); do \
		printf 'module "good%s" {\n  source = "./modules/good"\n  name   = "good%s"\n}\n\n' "$$i" "$$i"; \
	done; \
	printf 'module "zbad" {\n  source = "./modules/bad"\n}\n'; } > repo/infra/main.tf
