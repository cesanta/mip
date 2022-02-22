MDIR ?= ../../mongoose
WARN ?= -W -Wall -Wextra -Werror -Wundef -Wshadow -Wdouble-promotion -Wno-missing-field-initializers
OPTS ?= -g3 -Os
DEFS ?= -DMIP_DEBUG -DMG_ARCH=MG_ARCH_CUSTOM
INCL ?= -I. -I.. -I$(MDIR)
LIBS ?=
NIF  ?= vlan1 # wlp0s20f3
MAC  ?= $(shell ifconfig $(NIF) | perl -nle 'print $$1 if /ether\s+(\S+)/')
ARGS ?= -i $(NIF) #-mac $(MAC)
CFLAGS ?= $(WARN) $(OPTS) $(INCL) $(DEFS) 

all: test cpp vlan

test:
	$(CC) $(CFLAGS) unit_test.c -o /tmp/ut
	$(RUN) /tmp/ut

cpp:
	$(CXX) $(CFLAGS) unit_test.c -o /tmp/ut
	$(RUN) /tmp/ut

vlan: vlan.c mongoose_custom.c ../mip.c $(MDIR)/mongoose.c
	$(CC) $? $(CFLAGS) $(LIBS) -o /tmp/vlan
	$(RUN) sudo /tmp/vlan $(ARGS)

clean:
	rm -rf /tmp/vlan /tmp/ut *.dSYM *.o *.obj _CL*
