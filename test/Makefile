MDIR ?= ../../mongoose
WARN ?= -W -Wall -Wextra -Werror -Wundef -Wshadow -Wdouble-promotion
OPTS ?= -g3 -Os
DEFS ?= 
INCL ?= -I.. -I$(MDIR)
LIBS ?= -lpcap
NIF  ?= vlan1 # wlp0s20f3
MAC  ?= $(shell ifconfig $(NIF) | perl -nle 'print $$1 if /ether\s+(\S+)/')
ARGS ?= -i $(NIF) -mac $(MAC)
CFLAGS ?= $(WARN) $(OPTS) $(INCL) $(DEFS) 

all: test

test: vlan.c ../mip.c $(MDIR)/mongoose.c
	$(CC) $? $(CFLAGS) $(LIBS) -o vlan
	sudo setcap cap_net_raw,cap_net_admin=eip vlan
	$(RUN) ./vlan $(ARGS)

clean:
	rm -rf vlan *.dSYM *.o *.obj _CL*
