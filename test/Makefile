MDIR ?= ../../mongoose
WARN ?= -W -Wall -Wextra -Werror -Wundef -Wshadow -Wdouble-promotion -Wno-missing-field-initializers
OPTS ?= -g3 -Os
DEFS ?= -DMIP_ENABLE_DEBUG
INCL ?= -I.. -I$(MDIR)
LIBS ?= -lpcap
NIF  ?= vlan1 # wlp0s20f3
MAC  ?= $(shell ifconfig $(NIF) | perl -nle 'print $$1 if /ether\s+(\S+)/')
ARGS ?= -i $(NIF) #-mac $(MAC)
CFLAGS ?= $(WARN) $(OPTS) $(INCL) $(DEFS) 

all: test cpp vlan

test:
	$(CC) $(CFLAGS) unit_test.c -o ut
	$(RUN) ./ut

cpp:
	$(CXX) $(CFLAGS) unit_test.c -o ut
	$(RUN) ./ut

vlan: vlan.c ../mip.c $(MDIR)/mongoose.c
	$(CC) $? $(CFLAGS) $(LIBS) -o vlan
	$(RUN) sudo ./vlan $(ARGS)

clean:
	rm -rf vlan ut *.dSYM *.o *.obj _CL*
