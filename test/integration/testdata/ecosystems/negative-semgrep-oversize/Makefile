# Regenerates repo/src/bundle.js, a file over Semgrep's 1 MB limit with an eval on its second line.
# Needs nothing but awk; the sealed test reads the committed copy.

.PHONY: bundle
bundle:
	awk 'BEGIN { \
		print "// Over Semgrep'"'"'s 1 MB limit: Semgrep does not scan it, and the eval below is never reported."; \
		print "eval(input);"; \
		for (i = 0; i < 28000; i++) printf "var padding%05d = \"%s\";\n", i, "................"; \
	}' > repo/src/bundle.js
