#include "chrome.h"

int main() {
	// struct chromecast *cast = ;
	struct chromecast *cast = find_first_chromecast(); /* init_chromecast("...", 8009) */
	if (cast == NULL) {
		return 1;
	}
	fprintf(stderr, "[+] connected\n");

	fprintf(stderr, "[>] connect\n");
	send_fmt_string_payload(cast,
			"urn:x-cast:com.google.cast.tp.connection",
			"sender-0",
			"receiver-0",
			// "{\"type\": \"CONNECT\", \"origin\": {}, \"userAgent\": \"PyChromecast\", \"senderInfo\": {\"sdkType\": 2, \"version\": \"15.605.1.3\", \"browserVersion\": \"44.0.2403.30\", \"platform\": 4, \"systemVersion\": \"Macintosh; Intel Mac OS X10_10_3\", \"connectionType\": 1}}"
			"{\"type\": \"CONNECT\", \"origin\": {}, \"userAgent\": \"libchromecast\", \"senderInfo\": {\"sdkType\": 2, \"version\": \"0\", \"browserVersion\": \"0\", \"platform\": 4, \"systemVersion\": \"\", \"connectionType\": 1}}"
			);

	// get status
	fprintf(stderr, "[>] get status\n");
	send_fmt_string_payload(cast,
			"urn:x-cast:com.google.cast.receiver",
			"sender-0",
			"receiver-0",
			"{\"type\": \"GET_STATUS\", \"requestId\": %d}",
			++cast->request_id
			);

	/*
	// ping
	printf("[>] ping\n");
	send_string_payload(cast,
			"urn:x-cast:com.google.cast.tp.heartbeat",
			"{\"type\": \"PING\", \"requestId\": 2}",
			"sender-0",
			"receiver-0"
			);
	*/

	while (1) {
		CastMessage *msg = NULL;
		msg = get_next_message(cast);
		if (msg == NULL) {
			fprintf(stderr, "[*] no msg. skipping\n");
			sleep(1);
			continue;
		}
		if (strncmp(msg->namespace_, "urn:x-cast:com.google.cast.tp.heartbeat", strlen("urn:x-cast:com.google.cast.tp.heartbeat")) != 0) {
			fprintf(stderr, "[<] received msg\n");
			fprintf(stderr, "[<] NAMESPACE: %s\n", msg->namespace_);
			fprintf(stderr, "[<] PAYLOAD: %s\n", msg->payload_utf8);
			fprintf(stderr, "[<] SRC: %s\n", msg->source_id);
			fprintf(stderr, "[<] DST: %s\n", msg->destination_id);
		}

		// subscribe to current session
		if (!strncmp(msg->namespace_, "urn:x-cast:com.google.cast.receiver", strlen("urn:x-cast:com.google.cast.receiver"))) {
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
		// >

		if (strstr(msg->payload_utf8, "PING") != NULL) {
			send_fmt_string_payload(cast,
					"urn:x-cast:com.google.cast.tp.heartbeat",
					msg->source_id,
					msg->destination_id,
					"{\"type\": \"PONG\"}"
					);
		}

cleanup:
		extensions__api__cast_channel__cast_message__free_unpacked(msg, NULL);
		msg = NULL;
	}

	free_chromecast(cast);
	fprintf(stderr, "[+] disconnected\n");

	return 0;
}
