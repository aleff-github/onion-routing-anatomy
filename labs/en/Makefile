# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# English laboratory environment
.PHONY: test data image start verify status stop clean

# `test` covers torlab unit tests; it does not execute every book laboratory.
test:
	PYTHONPATH=code python3 -m pytest -q code/torlab/test

# Historical public data for labs 7, 15 and 19 (requires HTTPS only during preparation).
# Explicit, optional HTTPS download from Tor CollecTor; header check is NOT signature verification.
data:
	sh fetch-public-data.sh

image:
	$(MAKE) -C lab image

start:
	$(MAKE) -C lab start

# Combines torlab unit tests and Chutney's network check; not the 20 laboratory experiments.
verify:
	$(MAKE) test
	$(MAKE) -C lab verify

status:
	$(MAKE) -C lab status

stop:
	$(MAKE) -C lab stop

# Deletes lab/net, including generated keys and node identities; not a harmless reset.
clean:
	$(MAKE) -C lab clean
