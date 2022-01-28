MDIR ?= ../../mongoose
WARN ?= -W -Wall -Wextra -Werror -Wundef -Wshadow -Wdouble-promotion
OPTS ?= -g3 -Os
DEFS ?= 
INCL ?= -I../src -I$(MDIR)
LIBS ?= -lpcap
NETIF ?= vlan1
CFLAGS ?= $(WARN) $(OPTS) $(INCL) $(DEFS) 

all: test

test: unit_test.c ../src/mip.c $(MDIR)/mongoose.c
	$(CC) $? $(CFLAGS) $(LIBS) -o unit_test
	sudo setcap cap_net_raw,cap_net_admin=eip unit_test
	$(RUN) ./unit_test -i $(NETIF) -v

clean:
	rm -rf unit_test *.dSYM *.o *.obj _CL*
