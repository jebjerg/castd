#include "chrome.h"

int json_token_strcmp(const char *input, jsmntok_t *token, const char *match) {
	if (token->type == JSMN_STRING &&
			strlen(match) == token->end - token->start &&
			strncmp(input + token->start, match, token->end - token->start) == 0) {
		return 0;
	}
	return -1;
}

char *json_get_string_skip(const char *input, const char *key, const unsigned int skip) {
	char *value = NULL;

	jsmn_parser p;
	jsmntok_t *tokens = malloc(MAX_TOKENS * sizeof(jsmntok_t));
	if (tokens == NULL) {
		fprintf(stderr, "unable to allocate enough memory!\n");
		goto cleanup;
	}
	jsmn_init(&p);
	int num_tokens = jsmn_parse(&p, input, strlen(input), tokens, MAX_TOKENS);
	if (num_tokens < 0) {
		fprintf(stderr, "parsing failed, skipping\n");
		goto cleanup;
	}
#ifdef MINIMUM_MEMORY
	tokens = realloc(tokens, num_tokens * sizeof(jsmntok_t));
	if (tokens == NULL) {
		fprintf(stderr, "unable to reallocate memory!\n");
		goto cleanup;
	}
#endif
#ifdef DEBUG
	fprintf(stderr, "[%s] found %d tokens\n", key, num_tokens);
#endif

	for (int t = skip; t < num_tokens; t++) {
		if (json_token_strcmp(input, &tokens[t], key) == 0 && t + 1 < num_tokens) {
			asprintf(&value,
					"%.*s",
					tokens[t+1].end - tokens[t+1].start,
					input + tokens[t+1].start
					);
#ifdef DEBUG
			fprintf(stderr, "[=] %s: %s\n", key, value);
#endif
			break;
		}
	}
cleanup:
	free(tokens);
	return value;
}

char *json_get_string(const char *input, const char *key) {
	return json_get_string_skip(input, key, 0);
}

int json_get_array(const char *input, const char *key) {
	int value = -1;

	jsmn_parser p;
	jsmntok_t *tokens = malloc(MAX_TOKENS * sizeof(jsmntok_t));
	if (tokens == NULL) {
		fprintf(stderr, "unable to allocate enough memory!\n");
		goto cleanup;
	}
	jsmn_init(&p);
	int num_tokens = jsmn_parse(&p, input, strlen(input), tokens, MAX_TOKENS);
	if (num_tokens < 0) {
		fprintf(stderr, "parsing failed, skipping\n");
		goto cleanup;
	}
#ifdef MINIMUM_MEMORY
	tokens = realloc(tokens, num_tokens * sizeof(jsmntok_t));
	if (tokens == NULL) {
		fprintf(stderr, "unable to reallocate memory!\n");
		goto cleanup;
	}
#endif
#ifdef DEBUG
	fprintf(stderr, "[*] found %d tokens\n", num_tokens);
#endif

	for (int t = 0; t < num_tokens; t++) {
		if (json_token_strcmp(input, &tokens[t], key) == 0 && t + 1 < num_tokens &&
				tokens[t+1].type == JSMN_ARRAY) {
			if (tokens[t+1].size == 0) {
				value = 0;
				goto cleanup;
			} else {
				value = t+1+1; /* index of first element */
			}

		}
	}
cleanup:
	free(tokens);
	return value;
}

/* TODO:
struct chromecast_search {
	struct chromecast **chromecasts;
	unsigned int num_chromecasts;
};
struct chromecast_search find_chromecast();
*/

int socket_connect(char *hostname, int port) {
	struct hostent *host = gethostbyname(hostname);
	if (host == NULL) {
		fprintf(stderr, "socket_connect host == NULL\n");
		return -1;
	}
	struct sockaddr_in addr;
	int fd = socket(PF_INET, SOCK_STREAM, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "socket_connect unable to connect()\n");
		return -1;
	}
	return fd;
}

void free_chromecast(struct chromecast *cast) {
	if (cast == NULL) {
		return;
	}
	if (cast->session_id != NULL) {
		free(cast->session_id);
	}
	if (cast->ctx != NULL) {
		SSL_CTX_free(cast->ctx);
	}
	if (cast->ssl != NULL) {
		SSL_free(cast->ssl);
	}
	if (cast->fd > 0) {
		close(cast->fd);
	}
	if (cast != NULL) {
		free(cast);
	}
}

struct chromecast *init_chromecast(char *hostname, int port) {
	struct chromecast *ctx = calloc(1, sizeof(struct chromecast));
	if (ctx == NULL) {
		fprintf(stderr, "init_chromecast ctx == NULL\n");
		goto fail;
	}
	ctx->ctx = SSL_CTX_new(TLS_client_method());
	ctx->fd = socket_connect(hostname, port);
	if (ctx->fd == -1) {
		fprintf(stderr, "init_chromecast fd == -1\n");
		goto fail;
	}
	// TODO: needed? ctx->session_id = NULL;
	ctx->request_id = 0; // TODO: not needed, we use calloc. right?

	ctx->ssl = SSL_new(ctx->ctx);
	if (ctx->ssl == NULL) {
		fprintf(stderr, "init_chromecast ssl == NULL\n");
		goto fail;
	}
	if (SSL_set_fd(ctx->ssl, ctx->fd) == 0) {
		fprintf(stderr, "init_chromecast SSL_set_fd == NULL\n");
		goto fail;
	}

	if (SSL_connect(ctx->ssl) < 0) {
		fprintf(stderr, "init_chromecast SSL_connect < 0\n");
		goto fail;
	}
	return ctx;
fail:
	fprintf(stderr, "uh oh, init_chromecast failed!\n");
	free_chromecast(ctx);
	fprintf(stderr, "init_chromecast return NULL\n");
	return NULL;
}

CastMessage *get_next_message(struct chromecast *cast) {
	CastMessage *msg = NULL;
	uint32_t size_buf = 0;
	int ret;
	if ((ret = SSL_read(cast->ssl, &size_buf, sizeof(size_buf))) != sizeof(size_buf)) {
		printf("SSL_read size err: %d %d\n", ret, SSL_get_error(cast->ssl, ret));
		// SSL_ERROR_ZERO_RETURN
		return msg;
	}
	size_t msg_len = bswap_32(size_buf);
	uint8_t buf[msg_len];

	if ((ret = SSL_read(cast->ssl, buf, sizeof(buf))) != sizeof(buf)) {
		printf("SSL_read buf err: %d %d\n", ret, SSL_get_error(cast->ssl, ret));
		return msg;
	}

	msg = extensions__api__cast_channel__cast_message__unpack(NULL, msg_len, buf);
	if (msg == NULL) {
		printf("msg unpack failed");
		free_chromecast(cast);
		return NULL;
	}
	return msg;
}

void send_message(struct chromecast *cast, CastMessage msg) {
	uint8_t *buf = NULL;
	unsigned int size;
	size = extensions__api__cast_channel__cast_message__get_packed_size(&msg);
	buf = malloc(size+4);
	if (buf == NULL) {
		return;
	}
	extensions__api__cast_channel__cast_message__pack(&msg, buf+4);

	/*
	size_t msg_len = bswap_32(size);
	if (SSL_write(cast->ssl, &msg_len, sizeof(msg_len)) != sizeof(msg_len)) {
		return NULL;
	}
	*/
	*(buf+3) = size & 0xFF;
	*(buf+2) = (size >> 8) & 0xFF;
	*(buf+1) = (size >> 16) & 0xFF;
	*(buf+0) = (size >> 24) & 0xFF;

	if (SSL_write(cast->ssl, buf, size+4) != size+4) {
		return;
	}
	// fprintf(stderr, "[>] send_message OK [%d]\n", size);
	free(buf);
}

void send_string_payload(struct chromecast *cast, char *namespace, char *payload, char *source_id, char *destination_id) {
	CastMessage msg = EXTENSIONS__API__CAST_CHANNEL__CAST_MESSAGE__INIT;
	msg.protocol_version = EXTENSIONS__API__CAST_CHANNEL__CAST_MESSAGE__PROTOCOL_VERSION__CASTV2_1_0;
	msg.source_id = source_id;
	msg.destination_id = destination_id;
	msg.namespace_ = namespace;
	msg.payload_type = EXTENSIONS__API__CAST_CHANNEL__CAST_MESSAGE__PAYLOAD_TYPE__STRING;
	msg.payload_utf8 = payload;

#ifdef DEBUG
	fprintf(stderr, "[>] NAMESPACE: %s\n", msg.namespace_);
	fprintf(stderr, "[>] PAYLOAD: %s\n", msg.payload_utf8);
	fprintf(stderr, "[>] SRC: %s\n", msg.source_id);
	fprintf(stderr, "[>] DST: %s\n", msg.destination_id);
#endif

	send_message(cast, msg);
}

void send_fmt_string_payload(struct chromecast *cast, char *namespace, char *source_id, char *destination_id, char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	char *payload = NULL;
	int size = vasprintf(&payload, fmt, ap);
	va_end(ap);

	if (size >= 0) {
		send_string_payload(cast, namespace, payload, source_id, destination_id);
	}

	free(payload);
}

int find_chromecasts(struct chromecast **out_results) {
	return -1;
}

struct chromecast *find_first_chromecast() {
	struct chromecast *cast = NULL;
	struct mcast *cast_mdns_response = find_one_matching_multicast_dns_response("_googlecast._tcp.local");
	if (cast_mdns_response == NULL) {
		fprintf(stderr, "cast_mdns_response == NULL\n");
		goto find_exit;
	}
	cast = init_chromecast(inet_ntoa(cast_mdns_response->addr.sin_addr), 8009);
#ifdef DEBUG
	fprintf(stderr, "init_chromecast(%s, 8009) = %p\n", inet_ntoa(cast_mdns_response->addr.sin_addr), cast);
#endif
find_exit:
	if (cast_mdns_response != NULL) {
		free_multicast_dns_packet(cast_mdns_response);
	}
	return cast;
}

void cast_subscribe_session_id(struct chromecast *cast, unsigned int max_wait) {
	do {
		CastMessage *msg = NULL;
		msg = get_next_message(cast);
		if (msg == NULL) {
			fprintf(stderr, "[*] no msg. skipping\n");
			sleep(1);
			continue;
		}
		// got a packet!
		max_wait--;

		if (!strncmp(msg->namespace_, "urn:x-cast:com.google.cast.receiver", strlen("urn:x-cast:com.google.cast.receiver"))) {
			cast->session_id = json_get_string(msg->payload_utf8, "sessionId");
			if (cast->session_id != NULL) {
				send_fmt_string_payload(cast,
						"urn:x-cast:com.google.cast.tp.connection",
						"sender-0",
						cast->session_id,
						"{\"type\": \"CONNECT\", \"origin\": {}, \"userAgent\": \"libchromecast\", \"senderInfo\": {\"sdkType\": 2, \"version\": \"0\", \"browserVersion\": \"0\", \"platform\": 4, \"systemVersion\": \"\", \"connectionType\": 1}}"
						);
				max_wait = 0;
			}
		}
	} while (max_wait > 0);
}

void cast_launch_app(struct chromecast *cast, const char *app_id) {
	send_fmt_string_payload(cast,
			"urn:x-cast:com.google.cast.receiver",
			"sender-0",
			"receiver-0",
			"{\"type\": \"LAUNCH\", \"appId\": \"%s\", \"requestId\": %d}",
			app_id,
			++cast->request_id
	);
	cast_subscribe_session_id(cast, 10);
}

void cast_url(struct chromecast *cast, const char *url, const char *content_type, const char *stream_type) {
	cast_launch_app(cast, "CC1AD845");
	send_fmt_string_payload(cast,
			"urn:x-cast:com.google.cast.media",
			"sender-0",
			cast->session_id,
			"{\"type\": \"LOAD\", \"autoplay\": true, \"currentTime\": 0, \"customData\": {}, \"media\": {\"contentId\": \"%s\", \"contentType\": \"%s\", \"streamType\": \"%s\", \"metadata\": {}}, \"requestId\": %d, \"sessionId\": \"%s\"}",
			url,
			content_type,
			stream_type,
			++cast->request_id,
			cast->session_id
	);
}
