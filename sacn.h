/*
* sacn.h
* Marcus Birkin
* 06/02/2016
*/

#ifndef _SACN_H_
#define	_SACN_H_

/*
 * SACN protocol header.
 * ANSI E1.31 - 2009 : Entertainment Technology – Lightweight streaming protocol for transport of DMX512 using ACN
 * http://tsp.esta.org/tsp/documents/docs/E1-31_2009.pdf
 */
 
#define SACN_UDP_PORT_ACN_SDT 5568
#define SACN_BASE_IP_H 4026466304 //239.255.0.0
#define SACN_BASE_MAC_H 4026466304 //IPv4mcast_7f:00:00 (01:00:5e:7f:00:00)
#define SACN_MAX_UNIVERSES 63999 
#define SACN_MAX_PRIORITY 200
#define SACN_MAX_ADDRESS 512
#define SACN_E120_DIMMER_DATA 0x00
#define SACN_E120_ETC_PRIORITY 0xDD

/* sACN Packet Headers */
struct __attribute__((__packed__)) sacn_header {
	struct __attribute__((__packed__))  sacn_root {
		uint16_t	preamble;	/* Preamble size  */
		uint16_t	postamble;	/* Post-amble size */
		uint8_t		ident[12];	/* ACN packet identifier  */
		uint16_t	flags_len;	/* Flags and length */
		uint32_t    vector;		/* Vector */
		uint8_t		cid[16];	/* CID */
	} root;
	struct __attribute__((__packed__))  sacn_framing {
		uint16_t	flags_len;		/* Flags and length */
		uint32_t  	vector;			/* Vector */
		uint8_t		sourcename[64];	/* Source name */
		uint8_t		priority;		/* Priority */
		uint8_t		reserved[2]; 	/* Reserved */
		uint8_t		seq_num;		/* Sequence Number */
		uint8_t		options; 		/* Options */
		uint16_t	universe; 		/* Universe */
	} framing;
	struct __attribute__((__packed__)) sacn_dmp {
		uint16_t	flags_len;		/* Flags and length */
		uint8_t		vector;			/* Vector */
		uint8_t		type;			/* Address Type & Data Type */
		uint16_t	first_address;	/* First Property Address */
		uint16_t	address_increment; /* Address Increment */
		uint16_t	count;			/* Property value count */
		uint8_t		value_start;	/* Property values */
	} dmp;
};
 
/* Root layer consts*/
const uint16_t sacn_root_preamble = 0x0010;
const uint16_t sacn_root_postamble = 0x000;
const uint8_t sacn_root_ident[12] = "ASC-E1.17\0\0";
const uint8_t sacn_root_flags = 0x7;
const uint32_t sacn_root_vector = 0x00000004;

/* Framing layer consts */
const uint8_t sacn_framing_flags = 0x07;
const uint32_t sacn_framing_vector = 0x00000002;

/* DMP layer consts */
const uint8_t sacn_dmp_flags = 0x07;
const uint8_t sacn_dmp_vector = 0x02;
const uint8_t sacn_dmp_type = 0xa1;
const uint16_t sacn_dmp_first_address = 0x0000;
const uint16_t sacn_dmp_address_increment = 0x0001;

#endif
