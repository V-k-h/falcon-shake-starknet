.PHONY: all bench profile report clean test check-eff ratchet compare

# Full pipeline: measure -> profile -> render the HTML report.
all: bench profile report

# Efficiency ratchet: fail on any cost regression vs efficiency_baseline.json.
check-eff:
	python3 scripts/check_efficiency.py

# Lock measured improvements into the baseline (never raises an entry).
ratchet:
	python3 scripts/check_efficiency.py --update

bench:
	python3 scripts/run_bench.py

profile:
	python3 scripts/profile.py

report:
	python3 scripts/gen_report.py

test:
	snforge test

# Measure against other Cairo Falcon-512 verifiers at pinned commits (compare/).
compare:
	python3 compare/compare.py

clean:
	rm -rf target snfoundry_trace crates/*/snfoundry_trace
