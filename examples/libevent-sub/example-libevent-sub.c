#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <event.h>

#include <json.h>

#include "pubnub.h"
#include "pubnub-libevent.h"


/* In this example, we demonstrate subscription and unsubscription to multiple
 * channels. The program listens for keypresses; pressing a-z subscribes
 * or unsubscribes from channels respectively called "a", "b", etc.  Anything
 * received is shown on screen. */

static bool subscribed['z'-'a' + 1];


static void
subscribe_received(struct pubnub *p, enum pubnub_res result, char **channels, struct json_object *msg, void *ctx_data, void *call_data)
{
	/* ctx_data is (struct pubnub_libevent *) */
	/* call_data is NULL as that's what we passed to pubnub_subscribe_multi() */

	if (result == PNR_CANCELLED) {
		free(channels);
		return;
	}

	if (result != PNR_OK)
		/* This must be something fatal, we retry on recoverable
		 * errors. */
		exit(EXIT_FAILURE);

	if (json_object_array_length(msg) == 0) {
		printf("pubnub subscribe ok, no news\n");
	} else {
		for (int i = 0; i < json_object_array_length(msg); i++) {
			json_object *msg1 = json_object_array_get_idx(msg, i);
			printf("pubnub subscribe [%s]: %s\n", channels[i], json_object_get_string(msg1));
			free(channels[i]);
		}
	}
	free(channels);

	/* Loop. */
	pubnub_subscribe(p, NULL, -1, subscribe_received, NULL);
}


/* The "key pressed" callback. */

static void
read_stdin(int fd, short kind, void *userp)
{
	struct pubnub *p = userp;

	char letter;
	int n = read(0, &letter, 1);
	if (n < 0) {
		perror("read");
		exit(EXIT_FAILURE);
	} else if (n == 0) { // eof
		exit(EXIT_SUCCESS);
	}

	if (letter < 'a' || letter > 'z') {
		printf("Unknown input '%c'. Please press a letter 'a' to 'z'.\n", letter);
		return;
	}
	int i = letter - 'a';
	subscribed[i] = !subscribed[i];

	const char chname_buf[2] = { letter, 0 };
	const char *chname = chname_buf;
	if (subscribed[i]) {
		printf("Subscribed to channel '%c'\n", letter);
		pubnub_subscribe(p, /* channel name */ chname, -1, subscribe_received, NULL);
	} else {
		printf("Unsubscribed from channel '%c'\n", letter);
		pubnub_unsubscribe(p, /* channel names */ &chname, 1, -1, NULL, NULL);
	}
}


void
terminal_interactive()
{
	system("stty min 1 -icanon -echo");
}

void
terminal_cooked()
{
	system("stty cooked echo");
}

int
main(void)
{
	/* Set up the libevent library. */
	event_init();

	/* Set up the PubNub library, with a single shared context,
	 * using the libevent backend for event handling. */
	struct pubnub *p = pubnub_init("demo", "demo", &pubnub_libevent_callbacks, pubnub_libevent_init());

	/* Set the terminal interaction handlers. */
	terminal_interactive();
	atexit(terminal_cooked);

	struct event ev;
	event_set(&ev, 0 /*stdin*/, EV_READ | EV_PERSIST, read_stdin, p);
	event_add(&ev, NULL);

	/* Start the event loop. */
	event_dispatch();

	/* We should never reach here. */
	pubnub_done(p);
	return EXIT_SUCCESS;
}
