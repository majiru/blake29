</$objtype/mkfile
LIB=blake2.a
CFLAGS=$CFLAGS^(p)
OFILES=\
	blake2s.$O\
	blake2b.$O\
	blake2sp.$O\
	blake2bp.$O\
	blake2xs.$O\
	blake2xb.$O\

TESTS=${OFILES:%.$O=$O.%}

CLEANFILES=\
	$LIB\
	$OFILES\
	$TESTS\
	${OFILES:%.$O=%.$O.test}\

</sys/src/cmd/mklib

test:V:	$TESTS

run:VE: test
	for(i in $TESTS)
		echo -n $i^': ' && ./$i

%.$O.test:	%.c
	def=`{echo $stem | tr a-z A-Z}^'_SELFTEST'
	$CC $CFLAGS -o $target -D^$def $prereq

$O.%:	%.$O.test
	$LD $LFLAGS -o $target $prereq

6.blake2xs:	blake2xs.6.test blake2s.6
	$LD $LFALGS -o $target $prereq

6.blake2xb:	blake2xb.6.test blake2b.6
	$LD $LFALGS -o $target $prereq

6.blake2sp:	blake2sp.6.test blake2s.6
	$LD $LFALGS -o $target $prereq

6.blake2bp:	blake2bp.6.test blake2b.6
	$LD $LFALGS -o $target $prereq
