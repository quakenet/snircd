#
# Makefile for sbounce
#

CC=gcc
CFLAGS=-O3 -Wall -pedantic

PROG=sbounce
PREFIX=/opt/ircd
DEFINES=-DSETTINGSFILE=\"${PREFIX}/lib/bounce.conf\"\
		-DLOGFILE=\"${PREFIX}/lib/${PROG}.log\"\
		-DPIDFILE=\"${PREFIX}/lib/${PROG}.pid\"

all: ${PROG} logrotate.conf

${PROG}: ${PROG}.o
	gcc -O3 -lz -o ${PROG} ${PROG}.o

sbounce.o:
	gcc ${DEFINES} -c ${PROG}.c

logrotate.conf: logrotate.conf.in
	@sed -e 's,LOGFILE,${PREFIX}/lib/${PROG}.log,g'\
		-e 's,PIDFILE,${PREFIX}/lib/${PROG}.pid,g' <logrotate.conf.in >logrotate.conf

install: all
	@if [ ! -d ${PREFIX} -a ! -f ${PREFIX} ]; then \
	  echo "Creating directory ${PREFIX}"; \
	  mkdir ${PREFIX}; \
	  chmod 555 ${PREFIX}; \
	fi

	@if [ ! -d ${PREFIX}/bin -a ! -f ${PREFIX}/bin ]; then \
	  echo "Creating directory ${PREFIX}/bin"; \
	  mkdir ${PREFIX}/bin; \
	  chmod 555 ${PREFIX}/bin; \
	fi

	@if [ -f ${PREFIX}/bin/${PROG} ]; then \
	  echo "Saving existing ${PREFIX}/bin/${PROG} as .old"; \
	  mv ${PREFIX}/bin/${PROG} ${PREFIX}/bin/${PROG}.old; \
	fi

	cp ${PROG} ${PREFIX}/bin
	chmod 555 ${PREFIX}/bin/${PROG}

	@if [ -d /etc/logrotate.d ]; then \
	  echo "Installing /etc/logrotate.d/sbounce"; \
	  cp logrotate.conf /etc/logrotate.d/sbounce; \
	  chmod 444 /etc/logrotate.d/sbounce; \
	fi

clean:
	rm -f ${PROG}.o ${PROG} logrotate.conf
