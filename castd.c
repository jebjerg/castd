#include "chrome.h"

enum STATE {
	STATE_UNKNOWN = 0,
	STATE_NO_CAST_AVAILABLE = 1,	/* No Chromecast mDNS replies */
	STATE_CAST_BUSY = 2,		/* Chromecast app-mode, playing/buffering */
	STATE_CAST_IDLE = 3,		/* app-mode, idle */
	STATE_CAST_BACKDROP = 4,	/* no user app running */
};

struct state {
	enum STATE current;
	enum STATE last;
};

void set_state(struct state *state, enum STATE new_state) {
	if (state == NULL || state->current == new_state) {
		return;
	}
	if (state->current == STATE_UNKNOWN) {
		state->last = new_state;
	} else {
		state->last = state->current;
	}
	state->current = new_state;
}

// updates current/prev state iff new state info is available
void get_chromecast_state(struct chromecast *cast, struct state *state) {
	send_fmt_string_payload(cast,
			"urn:x-cast:com.google.cast.tp.connection",
			"sender-0",
			"receiver-0",
			"{\"type\": \"CONNECT\", \"origin\": {}, \"userAgent\": \"libchromecast\", \"senderInfo\": {\"sdkType\": 2, \"version\": \"0\", \"browserVersion\": \"0\", \"platform\": 4, \"systemVersion\": \"\", \"connectionType\": 1}}"
			);

	// get status
	send_fmt_string_payload(cast,
			"urn:x-cast:com.google.cast.receiver",
			"sender-0",
			"receiver-0",
			"{\"type\": \"GET_STATUS\", \"requestId\": %d}",
			++cast->request_id
			);

	unsigned int max_wait_pkt = 3;
	do {
		CastMessage *msg = NULL;
		msg = get_next_message(cast);
		max_wait_pkt--;
		if (msg == NULL) {
			fprintf(stderr, "[*] no msg. skipping\n");
			continue;
		}

		// handle ping/pong
		if (strstr(msg->payload_utf8, "PING") != NULL) {
			send_fmt_string_payload(cast,
					"urn:x-cast:com.google.cast.tp.heartbeat",
					msg->source_id,
					msg->destination_id,
					"{\"type\": \"PONG\"}"
					);
			goto next_pkg;
		}
		
		// TODO: handle CLOSE, as we may be subscribed to numerous apps eventually

		// chrome state
		if (!strncmp(msg->namespace_, "urn:x-cast:com.google.cast.receiver", strlen("urn:x-cast:com.google.cast.receiver"))) {
			char *isIdleScreen = json_get_string(msg->payload_utf8, "isIdleScreen");
			if (isIdleScreen && !strncmp(isIdleScreen, "true", strlen("true"))) {
				set_state(state, STATE_CAST_BACKDROP);
				max_wait_pkt = 0;
			} else /* subscribe and get status */ {
				cast->session_id = json_get_string(msg->payload_utf8, "sessionId");
				if (cast->session_id != NULL) {
					send_fmt_string_payload(cast,
							"urn:x-cast:com.google.cast.tp.connection",
							"sender-0",
							cast->session_id,
							"{\"type\": \"CONNECT\", \"origin\": {}, \"userAgent\": \"libchromecast\", \"senderInfo\": {\"sdkType\": 2, \"version\": \"0\", \"browserVersion\": \"0\", \"platform\": 6, \"systemVersion\": \"\", \"connectionType\": 1}}"
							);

					send_fmt_string_payload(cast,
							"urn:x-cast:com.google.cast.media",
							"sender-0",
							cast->session_id,
							"{\"type\": \"GET_STATUS\", \"requestId\": %d}",
							++cast->request_id
							);
				}
			}
			free(isIdleScreen);
		} else if (!strncmp(msg->namespace_, "urn:x-cast:com.google.cast.media", strlen("urn:x-cast:com.google.cast.media"))) {
			char *msg_type = json_get_string(msg->payload_utf8, "type");
			if (msg_type && !strncmp(msg_type, "MEDIA_STATUS", strlen("MEDIA_STATUS"))) {
				max_wait_pkt = 0;
				int status_res = json_get_array(msg->payload_utf8, "status");
				if (/* error */ status_res < 0) {

				} else if (/* empty array */ status_res == 0) {
					set_state(state, STATE_CAST_IDLE);
				} else { /* array start */
					char *playerState = json_get_string_skip(msg->payload_utf8, "playerState", (unsigned int)status_res);
					if (!strncmp(playerState, "PLAYING", strlen("PLAYING")) || !strncmp(playerState, "PAUSED", strlen("PAUSED")) || !strncmp(playerState, "BUFFERING", strlen("BUFFERING"))) {
						set_state(state, STATE_CAST_BUSY);
					} else if (!strncmp(playerState, "IDLE", strlen("IDLE"))) {
						set_state(state, STATE_CAST_IDLE);
					}
					free(playerState);
				}
			}
			free(msg_type);
		}
next_pkg:
		extensions__api__cast_channel__cast_message__free_unpacked(msg, NULL);
		msg = NULL;
	} while (max_wait_pkt > 0);
}

int main(int argc, char **argv) {
	// assume 1 chromecast only.
	struct state chrome_state;
	memset(&chrome_state, 0, sizeof(struct state));
	while (1) {
		// get new state
		struct chromecast *cast = find_first_chromecast();
		if (cast == NULL) {
			set_state(&chrome_state, STATE_NO_CAST_AVAILABLE);
			goto next_loop;
		}

		get_chromecast_state(cast, &chrome_state);

		if (chrome_state.current == STATE_NO_CAST_AVAILABLE) {
			if (chrome_state.last != chrome_state.current) {
				fprintf(stderr, "No cast available\n");
			}
			goto next_loop;
		}

#ifdef DEBUG
		fprintf(stderr, "Current status: %d [%d]\n", chrome_state.current, chrome_state.last);
#endif

		// evaluate last/current state
		if (chrome_state.current == STATE_CAST_BUSY) {
			goto next_loop;
		} else if (chrome_state.current == STATE_CAST_BACKDROP) {
			fprintf(stdout, "Suddenly, a wild Cast in backdrop-mode appears\n");
			cast_url(cast, argv[1], "video/mp4", "LIVE");
		}
next_loop:
		free_chromecast(cast);
		sleep(5);
		continue;
	}
	fprintf(stderr, "I'm done!");
}
