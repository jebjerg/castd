#include "mdns.h"

int create_multicast_socket(char *multicast_addr, unsigned short multicast_port) {
	int sock = 0;
	int ret = -1;
	struct addrinfo *local_ip = NULL;
	struct addrinfo *hints = calloc(1, sizeof(struct addrinfo));
	if (hints == NULL) {
		goto fail;
	}

	// 1. get local hostname
	char my_hostname[1024];
	memset(my_hostname, 0, 1024);
	if (gethostname(my_hostname, 1024)) {
		goto fail;
	}

	memset(hints, 0, sizeof(struct addrinfo));
	hints->ai_family = AF_INET;
	hints->ai_socktype = SOCK_STREAM;
	if (getaddrinfo(my_hostname, NULL, hints, &local_ip) != 0) {
		goto fail;
	}

	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
		perror("socket failed");
		goto fail;
	}

	// 2. SO_REUSEPORT
	int yes = 1;
	int no = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) == -1) {
		perror("Error setting reuseport");
		goto fail;
	}
	// 3. SO_REUSEADDR
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
		perror("Error setting reuseaddr");
		goto fail;
	}

	// 4. IP_ADD_MEMBERSHIP
	struct ip_mreq my_mreq;
	memset(&my_mreq, 0, sizeof(struct ip_mreq));
	my_mreq.imr_interface.s_addr = *(local_ip->ai_addr->sa_data); // TODO: cleanup
	my_mreq.imr_multiaddr.s_addr = inet_addr(multicast_addr);

	if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &my_mreq, sizeof(my_mreq)) == -1) {
		perror("Error adding membership");
		goto fail;
	}

	// 5. IP_MULTICAST_IF
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, local_ip->ai_addr, sizeof(local_ip->ai_addr)) == -1) {
		perror("Error setting if");
		goto fail;
	}

	// 6. IP_MULTICAST_LOOP
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &no, sizeof(no)) == -1) {
		perror("Error setting if");
		goto fail;
	}

	// 7. IP_MULTICAST_TTL
	unsigned char ttl = 255;
	if (setsockopt(sock, SOL_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == -1) {
		perror("Error setting MULTICAST TTL");
		goto fail;
	}

	// 8. IP_TTL
	if (setsockopt(sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) == -1) {
		perror("Error setting IP TTL");
		goto fail;
	}

	// 9. timeout
	struct timeval timeout;      
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
		perror("Error setting SO_RCVTIMEO");
		goto fail;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
		perror("Error setting SO_SNDTIMEO");
		goto fail;
	}

	// 9. bind
	struct sockaddr_in bind_addr;
	memset(&bind_addr, 0, sizeof(bind_addr));
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	bind_addr.sin_port = htons(multicast_port);

	if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == -1) {
		perror("bind failed");
		goto fail;
	}

	ret = sock;
fail:
	if (local_ip != NULL) {
		freeaddrinfo(local_ip);
	}
	if (hints != NULL) {
		free(hints);
	}
	return ret;
}

struct mcast *parse_multicast_dns_packet(char *data, size_t length) {
	struct mcast_hdr *mdns = (struct mcast_hdr *)data;
	struct mcast *pkt = calloc(1, sizeof(struct mcast));
	pkt->transaction_id           = bswap_16(mdns->transaction_id);
	pkt->flags                    = bswap_16(mdns->flags);
	pkt->num_questions            = bswap_16(mdns->num_questions);
	pkt->num_answers              = bswap_16(mdns->num_answers);
	pkt->num_auth_resources       = bswap_16(mdns->num_auth_resources);
	pkt->num_additional_resources = bswap_16(mdns->num_additional_resources);

	// fqdn
	char fqdn[length-sizeof(struct mcast_hdr)];
	char *fqdn_ptr = data + sizeof(struct mcast_hdr);
	unsigned int num_tokens = 0;
	unsigned int fqdn_pos = 0;
	for (unsigned int num_tokens = 0; fqdn < data+length; num_tokens++) { // NOTE: not msg+n, as n can be negative, dangerous if not checked
		unsigned char token_length = *fqdn_ptr++;
		if (token_length == 0) {
			break;
		}
		if (num_tokens > 0) {
			fqdn[fqdn_pos++] = '.';
		}
		memcpy(fqdn+fqdn_pos, fqdn_ptr, token_length);
		fqdn_pos += token_length;
		fqdn_ptr += token_length;
	}
	char fqdn_trimmed[fqdn_pos+1];
	memcpy(fqdn_trimmed, fqdn, fqdn_pos);
	fqdn_trimmed[fqdn_pos] = 0;
	pkt->fqdn = strdup(fqdn_trimmed);

	return pkt;
}

void free_multicast_dns_packet(struct mcast *pkt) {
	if (pkt == NULL) {
		return;
	}
	if (pkt->fqdn != NULL) {
		free(pkt->fqdn);
	}
	free(pkt);
}

int send_multicast_dns_packet(int sock, struct mcast *mdns) {
	struct sockaddr_in dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = inet_addr("224.0.0.251");
	dest.sin_port = htons(5353);
	int length = sizeof(dest);

	size_t pkt_length = sizeof(*mdns) - /* why 2?! */ 2* sizeof(char *) + strlen(mdns->fqdn) + /* fqdn length byte */ 1 + 1;
	char data[pkt_length];
	memset(data, 0, pkt_length);

	// pack struct
	unsigned int pkt_off = 0;
	unsigned short tmp = 0;

	PACK_SHORT(mdns->transaction_id);
	PACK_SHORT(mdns->flags);
	PACK_SHORT(mdns->num_questions);
	PACK_SHORT(mdns->num_answers);
	PACK_SHORT(mdns->num_auth_resources);
	PACK_SHORT(mdns->num_additional_resources);

	// fqdn
	memcpy(data+pkt_off+1, mdns->fqdn, strlen(mdns->fqdn));
	*(data+pkt_off) = 0; // NOTE: not needed

	for (int i = 1, last_null = 0, token_pos = 0, l = strlen(mdns->fqdn); i < l; i++) {
		if (data[pkt_off+i] == '.') {
			data[pkt_off+last_null] = i - 1 - last_null;
			last_null = i;
		} else if (i + 1 >= l) {
			data[pkt_off+last_null] = i - last_null + 1;
		}
	}
	pkt_off += strlen(mdns->fqdn) + 1;
	*(data+pkt_off++) = 0;

	PACK_SHORT(mdns->first_rr.type);
	PACK_SHORT(mdns->first_rr.class);

	if (sendto(sock, (void *)data, sizeof(data),
				0, (struct sockaddr *)&dest, length) != sizeof(data)) {
		return -1;
	}
	return 0;
}

int test_func() {
	int sock = create_multicast_socket("224.0.0.251", 5353);

	struct mcast chromecast_query = {
		.transaction_id = 0,
		.flags = 0,
		.num_questions = 1,
		.num_answers = 0,
		.num_auth_resources = 0,
		.num_additional_resources = 0,
		.fqdn = "_googlecast._tcp.local",
		// query
		.first_rr = (struct rr){
			.type = RR_TYPE_PTR,
			.class = RR_CLASS_IN,
		},
	};

	if (send_multicast_dns_packet(sock, &chromecast_query) < 0) {
		return -1;
	}

	unsigned int packet_num = 0;
	while (1) {
		char msg[0xffff];
		memset(msg, 0, 0xffff);
		struct sockaddr_in source;
		socklen_t source_length = sizeof(source);
		memset(&source, 0, source_length);
		ssize_t n = recvfrom(sock, msg, sizeof(msg), 0, (struct sockaddr *)&source, &source_length);
		if (n == 0) {
			break;
		} else if (n < 0) {
			perror("udp recvfrom error");
			break;
		}

		printf("received packet number: %d (%zd) from: %s:%d\n", ++packet_num, n, inet_ntoa(source.sin_addr), source.sin_port);
		if (/* multicast dns port, attempt to parse */ 1 /* source.sin_port == 5353 */) {
			struct mcast *m = parse_multicast_dns_packet(msg, n);
			if (m != NULL) {
				printf("mdns q#: %hu, a#: %hu, r#: %hu+%hu, fqdn: %s\n",
						m->num_questions,
						m->num_answers,
						m->num_auth_resources,
						m->num_additional_resources,
						m->fqdn);
			}
			free_multicast_dns_packet(m);
		}
	}

	return 0;
}

struct mcast *find_one_matching_multicast_dns_response(char *node) {
	int sock = create_multicast_socket("224.0.0.251", 5353);
	struct mcast *m = NULL;

	struct mcast chromecast_query = {
		.transaction_id = 0,
		.flags = 0,
		.num_questions = 1,
		.num_answers = 0,
		.num_auth_resources = 0,
		.num_additional_resources = 0,
		.fqdn = node,
		// query
		.first_rr = (struct rr){
			.type = RR_TYPE_PTR,
			.class = RR_CLASS_IN,
		},
	};

	if (send_multicast_dns_packet(sock, &chromecast_query) < 0) {
		goto exit;
	}

	unsigned int packet_num = 0;
	while (1) {
		char msg[0xffff];
		memset(msg, 0, 0xffff);
		struct sockaddr_in source;
		socklen_t source_length = sizeof(source);
		memset(&source, 0, source_length);
		ssize_t n = recvfrom(sock, msg, sizeof(msg), 0, (struct sockaddr *)&source, &source_length);
		if (n == 0) {
			break;
		} else if (n < 0) {
			perror("udp recvfrom error");
			break;
		}

		if (/* multicast dns port, attempt to parse */ 1 /* source.sin_port == 5353 */) {
			m = parse_multicast_dns_packet(msg, n);
			if (m != NULL && strncmp(m->fqdn, node, strlen(node)) == 0) {
				memcpy(&m->addr, &source, source_length);
				goto exit;
			}
			free_multicast_dns_packet(m);
			m = NULL;
		}
	}
exit:
	if (sock != -1) {
		close(sock);
	}
	return m;
}
