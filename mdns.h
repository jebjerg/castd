#ifndef MDNS_H
#define MDNS_H

#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <byteswap.h>
#include <libnetlink.h>

struct mcast_hdr {
	unsigned short transaction_id;
	unsigned short flags;
	unsigned short num_questions;
	unsigned short num_answers;
	unsigned short num_auth_resources;
	unsigned short num_additional_resources;
};

#define RR_TYPE_PTR 12
#define RR_TYPE_TXT 16
#define RR_TYPE_A 1
#define RR_TYPE_AAAA 28
#define RR_CLASS_IN 1

struct rr {
	unsigned short type;
	unsigned short class;
};

/* fixed size multicast dns packet
 * - one RR
 */

struct mcast {
	unsigned short transaction_id;
	unsigned short flags;
	unsigned short num_questions;
	unsigned short num_answers;
	unsigned short num_auth_resources;
	unsigned short num_additional_resources;
	char *fqdn;
	struct rr first_rr;
	struct sockaddr_in addr;
};

#define PACK_SHORT(n) tmp = htons(n); \
	memcpy(data+pkt_off, &tmp, sizeof(tmp)); \
	pkt_off += sizeof(tmp);

int create_multicast_socket(char *multicast_addr, unsigned short multicast_port);
struct mcast *parse_multicast_dns_packet(char *data, size_t length);
void free_multicast_dns_packet(struct mcast *pkt);
int send_multicast_dns_packet(int sock, struct mcast *mdns);
struct mcast *find_one_matching_multicast_dns_response(char *node);
#endif /* MDNS_H */
