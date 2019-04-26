#ifndef CHROME_H
#define CHROME_H

#define _GNU_SOURCE
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <byteswap.h>

#include <jsmn.h>
#include "cast_channel.pb-c.h"
#include "mdns.h"

typedef Extensions__Api__CastChannel__CastMessage CastMessage;

#define MAX_TOKENS 1024

struct chromecast {
	SSL_CTX *ctx;
	SSL *ssl;
	int fd;
	char *session_id;
	unsigned int request_id;
};

int json_token_strcmp(const char *input, jsmntok_t *token, const char *match);
char *json_get_string_skip(const char *input, const char *key, const unsigned int skip);
char *json_get_string(const char *input, const char *key);
int json_get_array(const char *input, const char *key);
int socket_connect(char *hostname, int port);
void free_chromecast(struct chromecast *cast);
struct chromecast *init_chromecast(char *hostname, int port);
CastMessage *get_next_message(struct chromecast *cast);
void send_message(struct chromecast *cast, CastMessage msg);
void send_string_payload(struct chromecast *cast, char *namespace, char *payload, char *source_id, char *destination_id);
void send_fmt_string_payload(struct chromecast *cast, char *namespace, char *source_id, char *destination_id, char *fmt, ...);
int find_chromecasts(struct chromecast **out_results);
struct chromecast *find_first_chromecast();
void cast_subscribe_session_id(struct chromecast *cast, unsigned int max_wait);
void cast_launch_app(struct chromecast *cast, const char *app_id);
void cast_url(struct chromecast *cast, const char *url, const char *content_type, const char *stream_type);

#endif /* CHROME_H */
