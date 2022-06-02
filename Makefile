
OUTDIR=build

# Default target
default: build16
.PHONY: default

# Recursive call targets
ifneq ($(MAKELEVEL), 0)

# Build aliases
build16: $(OUTDIR)/hhh.json
.PHONY: build16

# Compilation of P4 v16 source code
$(OUTDIR)/dleft.json: src/dleft.p4 $(wildcard src/includes/*.p4)
	${P4C} -o $@ --p4v 16 $<

# Run aliases
run: run16
.PHONY: run

# Run P4 v16 description of switch
run16: $(OUTDIR)/hhh.json
	sudo $(SSMN) --mode l2 --num-hosts 1 --behavioral-exe ${SWITCH_PATH} --json $< --cli ${CLI_PATH} --switch-config $(<:.json=.config)

# Clean-up
clean:
	rm -f ${OUTDIR}/*.json

# Pack
pack:
	rm -f p4code.zip
	zip -r --symlinks p4code.zip Makefile env.sh README.md src/* build/dleft.config doc/example.png tools/*.sh tools/*.py tools/mininet/* tools/controller/*

# Top-level make target
else
%:
	@bash -c "source ./env.sh; for var in \$$(compgen -v); do export \$$var; done; $(MAKE) --no-print-directory $@"
endif

