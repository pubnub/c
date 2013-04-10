#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <json.h>

#include "pubnub.h"
#include "pubnub-sync.h"

int
main(void)
{
	struct pubnub_sync *sync = pubnub_sync_init();
	struct pubnub *p = pubnub_init(
			/* publish_key */ "demo",
			/* subscribe_key */ "demo",
			/* secret_key for signing */ NULL,
			/* cipher_key for encryption */ NULL,
			/* origin, by default pubsub.pubnub.com" */ NULL,
			/* pubnub_callbacks */ &pubnub_sync_callbacks,
			/* pubnub_callbacks data */ sync);
	const char channel[] = "my_channel";
	json_object *msg;


	pubnub_history(
			/* struct pubnub */ p,
			/* channel */ channel,
			/* #messages */ 10,
			/* timeout */ 0,
			/* callback; sync needs NULL! */ NULL,
			/* callback data */ NULL);

	if (pubnub_sync_last_result(sync) != PNR_OK) {
		msg = pubnub_sync_last_response(sync);
		fprintf(stderr, "pubnub history error: %d [%s]\n", pubnub_sync_last_result(sync), json_object_get_string(msg));
		json_object_put(msg);
		return EXIT_FAILURE;
	}


	msg = pubnub_sync_last_response(sync);

	if (!json_object_is_type(msg, json_type_array)) {
		printf("Warning: pubnub history no error, but is not an array: %s\n",
			json_object_get_string(msg));
		json_object_put(msg);
		return EXIT_FAILURE;
	}

	int msg_count = json_object_array_length(msg);
	for (int i = 0; i < msg_count; i++) {
		json_object *msg1 = json_object_array_get_idx(msg, i);
		printf("%s:%d\t%s\n", channel, i, json_object_get_string(msg1));
	}

	json_object_put(msg);


	pubnub_done(p);
	return EXIT_SUCCESS;
}
