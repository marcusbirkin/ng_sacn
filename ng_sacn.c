/*
 * ng_sacn.c
 *
 * Marcus Birkin <marcus.birkin@gmail.com>
 *
 * based on the template ng_sample.h by Author: Julian Elischer <julian@freebsd.org>
 * $FreeBSD: releng/10.2/sys/netgraph/ng_sample.h 139823 2005-01-07 01:45:51Z isacnp $
 * $Whistle: ng_sample.h,v 1.3 1999/01/20 00:22:14 archie Exp $
 */

 /* For Debug */
#include <sys/syslog.h>
#include <sys/types.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/netisr.h>
#include <net/ethernet.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <machine/in_cksum.h>

#include <netgraph/ng_message.h>
#include <netgraph/ng_parse.h>
#include <netgraph/netgraph.h>

/* Helper macros */
#include "tmacro.h"

/* E1.31 sACN */
#include "sacn.h"
#include "sacn_draft.h"

#include "ng_sacn.h"

/* If you do complicated mallocs you may want to do this */
/* and use it for your mallocs */
#ifdef NG_SEPARATE_MALLOC
static MALLOC_DEFINE(M_NETGRAPH_SACN, "netgraph_sacn", "netgraph sacn node");
#else
#define M_NETGRAPH_SACN M_NETGRAPH
#endif

/*
 * This section contains the netgraph method declarations for the
 * sample node. These methods define the netgraph 'type'.
 */

static ng_constructor_t	ng_sacn_constructor;
static ng_rcvmsg_t ng_sacn_rcvmsg;
static ng_shutdown_t ng_sacn_shutdown;
static ng_newhook_t ng_sacn_newhook;
static ng_connect_t	ng_sacn_connect;
static ng_rcvdata_t	ng_sacn_rcvdata;
static ng_disconnect_t ng_sacn_disconnect;

/* Parse type for struct ng_sacn_generic */
static const struct ng_parse_struct_field ng_sacn_generic_type_fields[]
	= NG_SACN_SET_GENERIC_TYPE_INFO;
static const struct ng_parse_type ng_sacn_generic_type = {
	&ng_parse_struct_type,
	&ng_sacn_generic_type_fields
};

/* Parse type for struct ngsacnstat */
static const struct ng_parse_struct_field ng_sacn_stat_type_fields[]
	= NG_SACN_STATS_TYPE_INFO;
static const struct ng_parse_type ng_sacn_stat_type = {
	&ng_parse_struct_type,
	&ng_sacn_stat_type_fields
};

/* Parse type for struct ngsacnstat_universe */
static const struct ng_parse_struct_field ng_sacn_stat_universe_type_fields[]
	= NG_SACN_STATS_UNIVERSE_TYPE_INFO;
static const struct ng_parse_type ng_sacn_stat_universe_type = {
	&ng_parse_struct_type,
	&ng_sacn_stat_universe_type_fields
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_sacn_cmdlist[] = {
	{
		NGM_SACN_COOKIE,
		NGM_SACN_SET_BLOCK_START,
		"set_block_start",
		&ng_sacn_generic_type,
		NULL
	}, 
	{
		NGM_SACN_COOKIE,
		NGM_SACN_GET_BLOCK_START,
		"get_block_start",
		&ng_parse_uint16_type,
		&ng_sacn_generic_type,
	},
	{
		NGM_SACN_COOKIE,
		NGM_SACN_SET_BLOCK_LENGTH,
		"set_block_length",
		&ng_sacn_generic_type,
		NULL
	}, 
	{
		NGM_SACN_COOKIE,
		NGM_SACN_GET_BLOCK_LENGTH,
		"get_block_length",
		&ng_parse_uint16_type,
		&ng_sacn_generic_type,
	},
	{
		NGM_SACN_COOKIE,
		NGM_SACN_SET_PRIORITY,
		"set_priority",
		&ng_sacn_generic_type,
		NULL
	}, 
	{
		NGM_SACN_COOKIE,
		NGM_SACN_GET_PRIORITY,
		"get_priority",
		&ng_parse_uint16_type,
		&ng_sacn_generic_type,
	},
		{
		NGM_SACN_COOKIE,
		NGM_SACN_SET_UNIVERSE,
		"set_universe",
		&ng_sacn_generic_type,
		NULL
	}, 
	{
		NGM_SACN_COOKIE,
		NGM_SACN_GET_UNIVERSE,
		"get_universe",
		&ng_parse_uint16_type,
		&ng_sacn_generic_type,
	},
	{
		NGM_SACN_COOKIE,
		NGM_SACN_GET_STATUS,
		"get_status",
		NULL,
		&ng_sacn_stat_type,
	},
	{
		NGM_SACN_COOKIE,
		NGM_SACN_GET_STATUS_UNIVERSE,
		"get_status_universe",
		&ng_parse_uint16_type,
		&ng_sacn_stat_universe_type,
	},
	{ 0 }
};

/* Netgraph node type descriptor */
static struct ng_type typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_SACN_NODE_TYPE,
	.constructor =	ng_sacn_constructor,
	.rcvmsg =	ng_sacn_rcvmsg,
	.shutdown =	ng_sacn_shutdown,
	.newhook =	ng_sacn_newhook,
/*	.findhook =	ng_sacn_findhook, 	*/
	.connect =	ng_sacn_connect,	
	.rcvdata =	ng_sacn_rcvdata,
	.disconnect =	ng_sacn_disconnect,
	.cmdlist =	ng_sacn_cmdlist,
};
MODULE_DEPEND(ng_ether, ng_ether, 1, 1, 1);
NETGRAPH_INIT(sacn, &typestruct);

/* Information we store for each node */
struct SACN_UNIVERSE {
	uint16_t	block_start;
	uint16_t	block_length;
	uint8_t		priority;
	uint16_t 	universe;
	u_int		packets;	/* packet counter matched to this universe */
};

struct SACN_PRIV {
	node_p		node;	/* back pointer to node */
	hook_p		in;		/* hook pointer in */
	hook_p		out;	/* hook pointer out */
	u_int   	packets_in;		/* packet counter in */
	u_int   	packets_sacn;	/* packet counter sacn */
	struct SACN_UNIVERSE universe[SACN_MAX_UNIVERSES];	/* universe settings */
};
typedef struct SACN_PRIV *sacn_p;

/*
 * Allocate the private data structure. The generic node has already
 * been created. Link them together. We arrive with a reference to the node
 * i.e. the reference count is incremented for us already.
 *
 * If this were a device node than this work would be done in the attach()
 * routine and the constructor would return EINVAL as you should not be able
 * to creatednodes that depend on hardware (unless you can add the hardware :)
 */
static int
ng_sacn_constructor(node_p node)
{
	sacn_p privdata;

	/* Initialize private descriptor */
	privdata = malloc(sizeof(*privdata), M_NETGRAPH, M_WAITOK | M_ZERO);
	
	if(privdata == NULL) {
		return(ENOMEM);
	}

	/* Link structs together; this counts as our one reference to *nodep */
	NG_NODE_SET_PRIVATE(node, privdata);
	privdata->node = node;
	return (0);
}

/*
 * Give our ok for a hook to be added...
 * If we are not running this might kick a device into life.
 * Possibly decode information out of the hook name.
 * Add the hook's private info to the hook structure.
 * (if we had some). In this example, we assume that there is a
 * an array of structs, called 'channel' in the private info,
 * one for each active channel. The private
 * pointer of each hook points to the appropriate XXX_hookinfo struct
 * so that the source of an input packet is easily identified.
 * (a dlci is a frame relay channel)
 */
static int
ng_sacn_newhook(node_p node, hook_p hook, const char *name)
{
	const sacn_p sacnp = NG_NODE_PRIVATE(node);

	/* Which hook? */
	if(strcmp(name, NG_SACN_HOOK_IN) == 0) {
		sacnp->in = hook;
	}
	else if(strcmp(name, NG_SACN_HOOK_OUT) == 0) {
		sacnp->out = hook;	
	}
	else {
		return(EINVAL);
	}
	
	NG_HOOK_SET_PRIVATE(hook, sacnp);
	
	return(0);
}

/*
 * Get a netgraph control message.
 * We actually recieve a queue item that has a pointer to the message.
 * If we free the item, the message will be freed too, unless we remove
 * it from the item using NGI_GET_MSG();
 * The return address is also stored in the item, as an ng_ID_t,
 * accessible as NGI_RETADDR(item);
 * Check it is one we understand. If needed, send a response.
 * We could save the address for an async action later, but don't here.
 * Always free the message.
 * The response should be in a malloc'd region that the caller can 'free'.
 * A response is not required.
 * Theoretically you could respond defferently to old message types if
 * the cookie in the header didn't match what we consider to be current
 * (so that old userland programs could continue to work).
 */
static int
ng_sacn_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const sacn_p sacnp = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int error = 0;
	struct ng_mesg *msg;

	NGI_GET_MSG(item, msg);
	/* Deal with message according to cookie and command */
	switch (msg->header.typecookie) {
	case NGM_SACN_COOKIE:
		{
			switch (msg->header.cmd) {
			case NGM_SACN_SET_BLOCK_START:
			case NGM_SACN_SET_BLOCK_LENGTH:
			case NGM_SACN_SET_PRIORITY:
			case NGM_SACN_SET_UNIVERSE:
				{
					struct ng_sacn_generic *msg_args;
					/* Check that message is long enough. */
					if (msg->header.arglen != sizeof(*msg_args)) {
                        error = EINVAL;
                        break;
                    }
					msg_args = (struct ng_sacn_generic *)msg->data;
					
					/* Sanity check universe number */
					if (msg_args->universe  < 1 || msg_args->universe > SACN_MAX_UNIVERSES) {
						 error = EINVAL;
						 break;
					}
					
					switch (msg->header.cmd) {
					case NGM_SACN_SET_BLOCK_START:
						{
							/* Sanity check value */
							if (msg_args->value > SACN_MAX_ADDRESS) {
								 error = EINVAL;
								 break;
							}
								
							sacnp->universe[msg_args->universe].block_start = msg_args->value;
							
							log(LOG_DEBUG, "NGM_SACN_SET_BLOCK_START, Universe:%d, Value:%d,\r", 
								msg_args->universe,
								msg_args->value
								);
							break;
						}
					case NGM_SACN_SET_BLOCK_LENGTH:
						{
							/* Sanity check value */
							if (msg_args->value > SACN_MAX_ADDRESS) {
								 error = EINVAL;
								 break;
							}
								
							sacnp->universe[msg_args->universe].block_length = msg_args->value;
							
							log(LOG_DEBUG, "NGM_SACN_SET_BLOCK_LENGTH, Universe:%d, Value:%d,\r", 
								msg_args->universe,
								msg_args->value
								);
							break;
						}
					case NGM_SACN_SET_PRIORITY:
						{
							/* Sanity check value */
							if (msg_args->value > SACN_MAX_PRIORITY) {
								 error = EINVAL;
								 break;
							}
								
							sacnp->universe[msg_args->universe].priority = msg_args->value;
							
							log(LOG_DEBUG, "NGM_SACN_SET_BLOCK_PRIORITY, Universe:%d, Value:%d,\r", 
								msg_args->universe,
								msg_args->value
								);
							break;
						}
					case NGM_SACN_SET_UNIVERSE:
						{
							/* Sanity check value */
							if (msg_args->value > SACN_MAX_UNIVERSES) {
								 error = EINVAL;
								 break;
							}
								
							sacnp->universe[msg_args->universe].universe = msg_args->value;
							
							log(LOG_DEBUG, "NGM_SACN_SET_BLOCK_UNIVERSE, Universe:%d, Value:%d,\r", 
								msg_args->universe,
								msg_args->value
								);
							break;
						}
					}
					break;
				}
			case NGM_SACN_GET_BLOCK_START:
			case NGM_SACN_GET_BLOCK_LENGTH:
			case NGM_SACN_GET_PRIORITY:
			case NGM_SACN_GET_UNIVERSE:
				{					
					/* Requested universe */
					uint16_t universe;
					/* Check that message is long enough. */
					if(msg->header.arglen != sizeof(universe)) {
						error = EINVAL;
						break;
					}
					universe = *((u_int16_t *)&msg->data);
					
					/* Sanity check universe number */
					if (universe < 1 || universe > SACN_MAX_UNIVERSES) {
						 error = EINVAL;
						 break;
					}
					
					/* Response */
					struct ng_sacn_generic *resp_args;
					NG_MKRESPONSE(resp, msg, sizeof(*resp_args), M_NOWAIT);
					if (!resp) {
						error = ENOMEM;
						break;
					}
					resp_args = (struct ng_sacn_generic *) resp->data;
					
					resp_args->universe = universe;
					switch (msg->header.cmd) {
					case NGM_SACN_GET_BLOCK_START:
						{
							resp_args->value = sacnp->universe[universe].block_start;
							break;
						}
					case NGM_SACN_GET_BLOCK_LENGTH:
						{
							resp_args->value = sacnp->universe[universe].block_length;
							break;
						}
					case NGM_SACN_GET_PRIORITY:
						{
							resp_args->value = sacnp->universe[universe].priority;
							break;
						}
					case NGM_SACN_GET_UNIVERSE:
						{
							resp_args->value = sacnp->universe[universe].universe;
							break;
						}
					}
					break;
				}
			case NGM_SACN_GET_STATUS:
				{
					/* Response */
					struct ngsacnstat *resp_args;
					NG_MKRESPONSE(resp, msg, sizeof(*resp_args), M_NOWAIT);
					if (!resp) {
						error = ENOMEM;
						break;
					}
					resp_args = (struct ngsacnstat *) resp->data;
					
					resp_args->packets_in = sacnp->packets_in;
					resp_args->packets_sacn = sacnp->packets_sacn;
					break;
				}
			case NGM_SACN_GET_STATUS_UNIVERSE:
				{
					/* Requested universe */
					uint16_t universe;
					/* Check that message is long enough. */
					if(msg->header.arglen != sizeof(universe)) {
						error = EINVAL;
						break;
					}
					universe = *((u_int16_t *)&msg->data);
					
					/* Sanity check universe number */
					if (universe < 1 || universe > SACN_MAX_UNIVERSES) {
						 error = EINVAL;
						 break;
					}
					
					/* Response */
					struct ngsacnstat_universe *resp_args;
					NG_MKRESPONSE(resp, msg, sizeof(*resp_args), M_NOWAIT);
					if (!resp) {
						error = ENOMEM;
						break;
					}
					resp_args = (struct ngsacnstat_universe *) resp->data;

					resp_args->universe = universe;
					resp_args->packets = sacnp->universe[universe].packets;
					break;
				}
			default:
				{
					error = EINVAL;		/* unknown command */
					break;
				}
			}
			break;
		}
	default:
		error = EINVAL;			/* unknown cookie type */
		break;
	}

	/* Take care of synchronous response, if any */
	NG_RESPOND_MSG(error, node, item, resp);
	/* Free the message and return */
	NG_FREE_MSG(msg);
	return(error);
}


/*
 * Rebuild IP Checksum
 */
static void 
ng_sacn_ip_checksum(struct ip *ip)
{
	ip->ip_sum = 0;
	ip->ip_sum = in_cksum_hdr(ip);
}

/*
 * Rebuild UDP Checksum
 */
static void 
ng_sacn_udp_checksum(struct mbuf *m, struct udphdr *udp, const struct ip *ip)
{
	/* This tells mbuffer to calc or offload to the NIC if available */
	udp->uh_sum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr, udp->uh_ulen + htons(IPPROTO_UDP));
	m->m_pkthdr.csum_flags += CSUM_UDP;
    m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);
}

/*
 * sACN packet mangler
 */
static int
ng_sacn_mangle(struct mbuf *m, const sacn_p sacnp)
{	
	int buff_changed = 0;
	
	/* Headers */
	struct ether_header *eh;
	struct ip *ip;
	struct udphdr *uh;
	
	/* Packet counter */
	sacnp->packets_in++;
	
	/* Length Check for headers */
	const uint8_t header_len = sizeof(*eh) + sizeof(*ip) + sizeof(*uh);
	if((m->m_len < header_len) 
	&& (m = m_pullup(m, header_len)) == NULL) {
		return(EMSGSIZE);
	}
	
	/* Ethernet header */
	eh = mtod(m, struct ether_header *);
	
	/* IPv4 Only */
	if(ntohs(eh->ether_type) != ETHERTYPE_IP) {
		return(EPROTONOSUPPORT);
	} 
	
	/* IP header */
	ip = (struct ip *)(eh + 1);

	/* UDP Only */
	if(ip->ip_p != IPPROTO_UDP) {
		return(EPROTONOSUPPORT);
	} 
	
	/* UDP Header */
	uh = (struct udphdr *)(ip + 1);
	
	/* Check UDP destination port */
	if (ntohs(uh->uh_dport) != SACN_UDP_PORT_ACN_SDT) {
		/* Not sACN or non-standard port */
		return(EPROTONOSUPPORT);
	}
		
	/* IP destination check (multicast only) */
	if ( (ip->ip_dst.s_addr > htonl(SACN_BASE_IP_H)) && (ip->ip_dst.s_addr < htonl(SACN_BASE_IP_H + SACN_MAX_UNIVERSES)) ) {
		/* Valid sACN Multicast address */
		uint16_t universe = (ntohl(ip->ip_dst.s_addr) - SACN_BASE_IP_H);
		if ( (sacnp->universe[universe].block_start == 1) && (sacnp->universe[universe].block_length == SACN_MAX_ADDRESS) ) {
			/* Block entire universe? */
			
			/* Increase universe packet counter */
			sacnp->universe[universe].packets++;
			
			/* Then lets drop it */
			return(ECONNREFUSED);
		}
	}
	
	/* UDP Payload */
	uint8_t *udp_payload = (uint8_t *)(uh + 1);
	
	/* UDP Payload length check */
	u_short udp_payload_len = ntohs(uh->uh_ulen) - sizeof(*uh);
	if((m->m_len < header_len + udp_payload_len) 
	&& (m = m_pullup(m, header_len + udp_payload_len)) == NULL) {
		return(EMSGSIZE);
	}

	/* sACN header length check */
	if ( udp_payload_len < sizeof(struct sacn_header) )
	{
		/* Too short to be sACN */
		return(EPROTONOSUPPORT);
	}

	/* sACN Packet */
	struct sacn_header *sacn = (struct sacn_header *)(udp_payload);
	
	/* Check sACN Root layer */
	uint8_t root_flags = (ntohs(sacn->root.flags_len) & 0xF000) >> (3*4); // Extract flag, high 4 bits
	if 
	(
		(ntohs(sacn->root.preamble) != sacn_root_preamble) ||
		(memcmp(sacn->root.ident, sacn_root_ident, sizeof(sacn->root.ident))) ||
		(ntohs(sacn->root.postamble) != sacn_root_postamble) ||
		(root_flags != sacn_root_flags)
	)
	{
		/* Not sACN */
		return(EPROTONOSUPPORT);
	}
	
	/* Check sACN Root layer - Draft vs Ratified */
	int draft;
	if ((ntohl(sacn->root.vector) == sacn_root_vector)) {
		draft = false;
	} else if ((ntohl(sacn->root.vector) == sacn_draft_root_vector)) {
		draft = true;
		return(EPROTONOSUPPORT);
	} else {
		/* Not sACN */
		return(EPROTONOSUPPORT);
	}
	
	/* Check sACN Framing layer */
	const uint8_t framing_flags = (ntohs(sacn->framing.flags_len) & 0xF000) >> (3*4); // Extract flag, high 4 bits	
	if 
	(
		(framing_flags != sacn_framing_flags) ||	 
		(ntohl(sacn->framing.vector) != sacn_framing_vector)
	)
	{
		/* Not sACN */
		return(EPROTONOSUPPORT);
	}
	
	/* Check sACN DMP layer */
	const uint8_t dmp_flags = (ntohs(sacn->framing.flags_len) & 0xF000) >> (3*4); // Extract flag, high 4 bits	
	if 
	(
		(dmp_flags != sacn_dmp_flags) ||	 
		(sacn->dmp.vector != sacn_dmp_vector) ||
		(sacn->dmp.type != sacn_dmp_type) ||
		(ntohs(sacn->dmp.first_address) != sacn_dmp_first_address) ||
		(ntohs(sacn->dmp.address_increment) != sacn_dmp_address_increment)
	)
	{
		/* Not sACN */
		return(EPROTONOSUPPORT);
	}
	
	/* sACN total length check */
	if ( udp_payload_len < (sizeof(struct sacn_header) - 1) + ntohs(sacn->dmp.count) )
	{
		/* Shorter than reported - Therefore corrupt sACN packet */
		/* Then lets drop it */
		return(ECONNREFUSED);
	}
	
	/* It's a valid sACN packet, increase counter! */
	sacnp->packets_sacn++;
	
	/* Get universe number */
	uint16_t universe = ntohs(sacn->framing.universe);
	
	/* Increase universe packet counter */
	sacnp->universe[universe].packets++;
	
	/* Block dimmer data, if needed */
	if (sacn->dmp.value_start == SACN_E120_DIMMER_DATA) {
		if (sacnp->universe[universe].block_start && sacnp->universe[universe].block_length) {
			uint16_t start = MIN(sacnp->universe[universe].block_start, ntohs(sacn->dmp.count)) - 1;
			uint16_t length = MIN(sacnp->universe[universe].block_length, ntohs(sacn->dmp.count) - start - 1);
			
			if (start == 1 && length == SACN_MAX_ADDRESS) {
				/* Block entire universe? */
				/* Then lets drop it */
				return(ECONNREFUSED);
			}

			memset(
				&sacn->dmp.value_start + start + 1, // +1 for start code
				0,
				length
			);
		}
		
		/* We've altered the buffer */
		buff_changed = 1;
	}
		
	/* Change priority, if needed */
	if (sacnp->universe[universe].priority) {
		sacn->framing.priority = sacnp->universe[universe].priority;
		
		/* DD packets */
		if (sacn->dmp.value_start == SACN_E120_ETC_PRIORITY) {
			memset(
				&sacn->dmp.value_start + 1, // +1 for start code
				sacnp->universe[universe].priority,
				ntohs(sacn->dmp.count) - 1 // -1 for start code
			);	
		}
		
		/* We've altered the buffer */
		buff_changed = 1;
	}
		
	/* Change universe, if needed */
	if (sacnp->universe[universe].universe) {
		sacn->framing.universe = htons(sacnp->universe[universe].universe);
		
		/* Mangle dest IP */
		ip->ip_dst.s_addr = htonl(SACN_BASE_IP_H + sacnp->universe[universe].universe);
		
		/* Mangle dest MAC */
		eh->ether_dhost[4] = HIBYTE(sacnp->universe[universe].universe);
		eh->ether_dhost[5] = LOBYTE(sacnp->universe[universe].universe);
		
		/* Reform IP checksum */
		ng_sacn_ip_checksum(ip);
		
		/* We've altered the buffer */
		buff_changed = 1;
	}
		 
	/* Reform UDP checksum */
	if (buff_changed) {
		ng_sacn_udp_checksum(m, uh, ip);
	}
	
	return(0);
}

/*
 * Receive data, and do something with it.
 * Actually we receive a queue item which holds the data.
 * If we free the item it will also free the data unless we have
 * previously disassociated it using the NGI_GET_M() macro.
 * Possibly send it out on another link after processing.
 * Possibly do something different if it comes from different
 * hooks. The caller will never free m, so if we use up this data or
 * abort we must free it.
 *
 * If we want, we may decide to force this data to be queued and reprocessed
 * at the netgraph NETISR time.
 * We would do that by setting the HK_QUEUE flag on our hook. We would do that
 * in the connect() method.
 */
static int
ng_sacn_rcvdata(hook_p hook, item_p item)
{
	const sacn_p sacnp = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	int error = 0;
	struct mbuf *m;

	NGI_GET_M(item, m);
	if(hook == sacnp->in) {
		/* in to out - process packet */
		error = ng_sacn_mangle(m, sacnp);
		if (error == ECONNREFUSED) {
			/* Throw away */
			NG_FREE_ITEM(item);
			NG_FREE_M(m);
		} else {
			/* Forward */
			NG_FWD_NEW_DATA(error, item, sacnp->out, m);
		}
	}
	else if(hook == sacnp->out) {
		/* out to in - pass through */
		NG_FWD_NEW_DATA(error, item, sacnp->in, m);
	}
	else {
		/* Throw away */
		NG_FREE_ITEM(item);
		NG_FREE_M(m);
		error = ENETUNREACH;
	}
	
	return(error);
}

/*
 * Do local shutdown processing..
 * All our links and the name have already been removed.
 * If we are a persistant device, we might refuse to go away.
 * In the case of a persistant node we signal the framework that we
 * are still in business by clearing the NGF_INVALID bit. However
 * If we find the NGF_REALLY_DIE bit set, this means that
 * we REALLY need to die (e.g. hardware removed).
 * This would have been set using the NG_NODE_REALLY_DIE(node)
 * macro in some device dependent function (not shown here) before
 * calling ng_rmnode_self().
 */
static int
ng_sacn_shutdown(node_p node)
{
	const sacn_p privdata = NG_NODE_PRIVATE(node);

#ifndef PERSISTANT_NODE
	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);
	free(privdata, M_NETGRAPH);
#else
	if (node->nd_flags & NGF_REALLY_DIE) {
		/*
		 * WE came here because the widget card is being unloaded,
		 * so stop being persistant.
		 * Actually undo all the things we did on creation.
		 */
		NG_NODE_SET_PRIVATE(node, NULL);
		NG_NODE_UNREF(privdata->node);
		free(privdata, M_NETGRAPH);
		return (0);
	}
	NG_NODE_REVIVE(node);		/* tell ng_rmnode() we will persist */
#endif /* PERSISTANT_NODE */
	return (0);
}

/*
 * This is called once we've already connected a new hook to the other node.
 * It gives us a chance to balk at the last minute.
 */
static int
ng_sacn_connect(hook_p hook)
{
	return (0);
}

/*
 * Hook disconnection
 *
 * For this type, removal of the last link destroys the node
 */
static int
ng_sacn_disconnect(hook_p hook)
{
	if ((NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0)
	&& (NG_NODE_IS_VALID(NG_HOOK_NODE(hook)))) /* already shutting down? */
		ng_rmnode_self(NG_HOOK_NODE(hook));
	return (0);
}
