DIAGRAMS := \
	keep/sgx/syscall.msc.png \
	attestation/amd/sev/certchain.dot.png \
	attestation/amd/sev/process.msc.png \
	attestation/ibm/pef/certchain.dot.png \
	attestation/ibm/pef/process.msc.png

all: $(DIAGRAMS)

%.dot.png: %.dot
	dot -T png -o $@ $<

%.msc.png: %.msc
	mscgen -T png -o $@ $<

.PHONY: diagrams

diagrams:
	echo $(DIAGRAMS)
