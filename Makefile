KMOD	=	ng_sacn
SRCS	=	ng_sacn.c
KO	=	${KMOD}.ko
#COPTS	=	-g

KLDLOAD		= /sbin/kldload
KLDUNLOAD	= /sbin/kldunload

load: ${KO}
	${KLDLOAD} -v ./${KO}

unload: ${KO}
	${KLDUNLOAD} -v -n ${KO}


.include <bsd.kmod.mk>
