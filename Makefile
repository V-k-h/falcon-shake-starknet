.PHONY: all bench profile report clean test check-eff ratchet compare sweep devnet

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

# Cost of every signature in benchmarks/data/signatures.json, plus rejection paths.
sweep:
	python3 benchmarks/signatures.py

# Real Falcon-signed transactions on a local starknet-devnet. Needs FALCON_PY=<falcon.py clone>
# and a PYTHON with its dependencies (numpy, pycryptodome, beartype).
PYTHON ?= python3
devnet:
	$(PYTHON) benchmarks/devnet.py --falcon-py $(FALCON_PY)

clean:
	rm -rf target snfoundry_trace crates/*/snfoundry_trace
