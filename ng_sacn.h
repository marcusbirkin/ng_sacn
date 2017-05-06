/*
 * ng_sacn.h
 *
 * Marcus Birkin <marcus.birkin@gmail.com>
 *
 * based on the template ng_sample.h by Author: Julian Elischer <julian@freebsd.org>
 * $FreeBSD: releng/10.2/sys/netgraph/ng_sample.h 139823 2005-01-07 01:45:51Z imp $
 * $Whistle: ng_sample.h,v 1.3 1999/01/20 00:22:14 archie Exp $
 */


#ifndef _NETGRAPH_NG_SACN_H_
#define _NETGRAPH_NG_SACN_H_

/* Node type name. This should be unique among all netgraph node types */
#define NG_SACN_NODE_TYPE	"sacn"

/* Node type cookie. Should also be unique. This value MUST change whenever
   an incompatible change is made to this header file, to insure consistency.
   The de facto method for generating cookies is to take the output of the
   date command: date -u +'%s' */
#define NGM_SACN_COOKIE		1456406301

/* Hook names */
#define NG_SACN_HOOK_IN		"in"
#define NG_SACN_HOOK_OUT	"out"

/* Netgraph commands understood by this node type */
enum {
	NGM_SACN_SET_BLOCK_START = 1,
	NGM_SACN_GET_BLOCK_START,
	NGM_SACN_SET_BLOCK_LENGTH,
	NGM_SACN_GET_BLOCK_LENGTH,
	NGM_SACN_SET_PRIORITY,
	NGM_SACN_GET_PRIORITY,
	NGM_SACN_SET_UNIVERSE,
	NGM_SACN_GET_UNIVERSE,
	NGM_SACN_GET_STATUS,
	NGM_SACN_GET_STATUS_UNIVERSE
};

/* For NGM_SACN_SET_XXX control message. */
struct ng_sacn_generic {
	u_int16_t		universe;		/* universe to match */
	u_int16_t		value;			/* value */
};
/* Keep this in sync with the above structure definition.  */
#define	NG_SACN_SET_GENERIC_TYPE_INFO			{		\
	{ "universe",		&ng_parse_uint16_type	},		\
	{ "value",		&ng_parse_uint16_type	},		\
	{ NULL }						\
}

/* This structure is returned by the NGM_SACN_GET_STATUS command */
struct ngsacnstat {
	u_int32_t   packets_in;		/* packets in */
	u_int32_t   packets_sacn;	/* packets in that are sacn */
};

/* Keep this in sync with the above structure definition.  */
#define NG_SACN_STATS_TYPE_INFO	{				\
	  { "packets_in",	&ng_parse_uint32_type	},	\
	  { "packets_sacn",	&ng_parse_uint32_type	},	\
	  { NULL }						\
}

/* This structure is returned by the NGM_SACN_UNIVERSE_GET_STATUS command */
struct ngsacnstat_universe {
	u_int16_t	universe;		/* universe number */
	u_int32_t	packets; 		/* packets */
};
/* Keep this in sync with the above structure definition.  */
#define NG_SACN_STATS_UNIVERSE_TYPE_INFO	{				\
	  { "universe",		&ng_parse_uint16_type	},	\
	  { "packets",		&ng_parse_uint32_type	},	\
	  { NULL }						\
}

#endif /* _NETGRAPH_NG_SACN_H_ */
