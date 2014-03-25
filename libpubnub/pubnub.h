#ifndef PUBNUB__PubNub_h
#define PUBNUB__PubNub_h

#if !defined(_MSC_VER)
# include <stdbool.h>
#elif !defined(__cplusplus)
typedef int bool;
# define false 0
# define true 1
#endif

#include <time.h>

#include <json.h>

#ifdef __cplusplus
extern "C" {
#endif


/** PubNub structures and constants */

/* struct pubnub is a PubNub context, holding the complete PubNub
 * library state, especially the credentials and a persistent HTTP
 * connection.  The structure should be treated as completely opaque
 * by the application.
 *
 * Only one method may operate on a single context at once - this means
 * that if a subscribe is in progress, you cannot publish in the same
 * context; either wait or use multiple contexts. If the same context
 * is used in multiple threads, the application must ensure locking to
 * prevent improper concurrent access. */
struct pubnub;

#if defined(__MINGW32__) || defined(_MSC_VER)
struct timespec {
	int tv_sec;
	int tv_nsec;
};
#endif

#if defined _MSC_VER || defined __cplusplus
#define SFINIT(f, v) v	
#else
#define SFINIT(f, v) f = v
#endif


/* Result codes for PubNub methods. */
enum pubnub_res {
	/* Success. */
	PNR_OK,
	/* Another method already in progress. (Will not retry.) */
	PNR_OCCUPIED,
	/* Time out before the request has completed. */
	PNR_TIMEOUT,
	/* Communication error. response is string object with the error. */
	PNR_IO_ERROR,
	/* HTTP error. response contains number object with the status code. */
	PNR_HTTP_ERROR,
	/* Unexpected input in received JSON. */
	PNR_FORMAT_ERROR,
	/* Cancellation by user request. A chance to free resources associated
	 * with an ongoing subscribe. (Will not retry.) */
	PNR_CANCELLED,
};

/* ctx_data is callbacks data passed to pubnub_init().
 * call_data is callbacks data passed to method call. */

/* Callback functions to user code upon completion of various methods. */
/* Note that if the function wants to preserve the response, it should
 * bump its reference count, otherwise it will be auto-released after
 * callback is done. channels[], on the other hand, are dynamically
 * allocated and both the array and its individual items must be free()d
 * by the callee; to ease iteration by user code, there is guaranteed to
 * be as many elements as there are messages in the channels list, and
 * an extra NULL pointer at the end of the array. */
typedef void (*pubnub_publish_cb)(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data);
typedef void (*pubnub_subscribe_cb)(struct pubnub *p, enum pubnub_res result, char **channels, struct json_object *response, void *ctx_data, void *call_data);
typedef void (*pubnub_unsubscribe_cb)(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data);
typedef void (*pubnub_history_cb)(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data);
typedef void (*pubnub_here_now_cb)(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data);
typedef void (*pubnub_time_cb)(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data);

/* struct pubnub_callbacks describes the way PubNub calls coordinate
 * with the rest of the application; they tell what happens on pubnub
 * methods calls, enabling the application to either use the API
 * synchronously, use a custom callback system or rely on an external
 * event loop (such as GTK's, libevent etc.). */
struct pubnub_callbacks {
	/* Functions for low-level event handling. */
	/* This is the main interface to event loop wrappers. */

	/* Watch for events on a given file descriptor.
	 * (mode & 1) means watching for input, (mode & 2) means
	 * watching for output (both bits can be set). In case
	 * mode needs to be changed, rem_socket() is called first,
	 * then add_socket() with new terms. cb(mode) has same
	 * bit assignments (to be set based on events), plus (mode & 4)
	 * for error event. */
	void (*add_socket)(struct pubnub *p, void *ctx_data, int fd, int mode,
			void (*cb)(struct pubnub *p, int fd, int mode, void *cb_data), void *cb_data);
	/* Stop watching given file descriptor. */
	void (*rem_socket)(struct pubnub *p, void *ctx_data, int fd);
	/* Register a timeout handler, calling given callback after
	 * the specified time interval. Note that a subsequent call
	 * should override the previous timeout; call with NULL
	 * callback should just cancel the timeout (though currently
	 * never issued), and so should a stop_wait call. */
	void (*timeout)(struct pubnub *p, void *ctx_data, const struct timespec *ts,
			void (*cb)(struct pubnub *p, void *cb_data), void *cb_data);
	/* Declare that events should be awaited now.
	 * This is usually called at the end of the main method
	 * body and is expected to just register the timeout
	 * callback. However, synchronous interface may actually
	 * block until a stop_wait call here. */
	void (*wait)(struct pubnub *p, void *ctx_data);
	/* Stop the registered timeout wait, declaring that all
	 * relevant events have been received and handled by now.
	 * This is usually called at the end of the final socket
	 * callback, maybe after unregistering socket events. */
	void (*stop_wait)(struct pubnub *p, void *ctx_data);
	/* Deinitialize. Called from pubnub_done(), should remove
	 * all event listeners associated with this context. */
	void (*done)(struct pubnub *p, void *ctx_data);

	/* Default method callbacks. */
	/* These are called on method finish if user passes NULL
	 * as the callback in a particular method call. */

	pubnub_publish_cb publish;
	pubnub_subscribe_cb subscribe;
	pubnub_unsubscribe_cb unsubscribe;
	pubnub_history_cb history;
	pubnub_here_now_cb here_now;
	pubnub_time_cb time;

	/* This extra pointer is reserved for forward binary
	 * compatibility in case more callbacks need to be added;
	 * then, it will point to a chained callback structure
	 * or some entirely new and more flexible contraption. */
	void *unused;
};


/** PubNub context methods */

/* Initialize the PubNub context and set the compulsory parameters
 * @publish_key and @subscribe_key.
 *
 * @cb is a set of callbacks implementing libpubnub's needs for
 * socket and timer handling, plus default completion callbacks
 * for the API requests.  Typically, @cb value will be a structure
 * exported by one of the frontends and @cb_data will be the
 * appropriate frontend context.  However, you can also customize
 * these or pass your own structure.
 *
 * This function will also initialize the libcurl library. This has
 * an important connotation for multi-threaded programs, as the first
 * call to this function will imply curl_global_init() call and that
 * function is completely thread unsafe. If you need to call
 * pubnub_init() with other threads already running (and not even
 * necessarily doing anything PubNub-related), call curl_global_init()
 * early before spawning other threads.
 *
 * One PubNub context can service only a single request at a time
 * (and you must not access it from multiple threads at once), however
 * you can maintain as many contexts as you wish. */
struct pubnub *pubnub_init(const char *publish_key, const char *subscribe_key,
			const struct pubnub_callbacks *cb, void *cb_data);

/* Deinitialize the given PubNub context, freeing all memory that is
 * associated with it.
 *
 * Note that calling pubnub_done() while a PubNub call is in progress
 * is undefined as call cancellation is currently not supported.  It may
 * work fine in practice depending on your event loop, but your callback
 * will not be called (this may change in the future). */
void pubnub_done(struct pubnub *p);


/* Set the secret key that is used for signing published messages
 * to confirm they are genuine. Using the secret key is optional. */
void pubnub_set_secret_key(struct pubnub *p, const char *secret_key);

/* Set the cipher key that is used for symmetric encryption of messages
 * passed over the network (publish, subscribe, history). Using the
 * cipher key is optional. */
void pubnub_set_cipher_key(struct pubnub *p, const char *cipher_key);

/* Set the origin server name. By default, http://pubsub.pubnub.com/
 * is used. */
void pubnub_set_origin(struct pubnub *p, const char *origin);

/* Retrieve the currently used UUID of this PubNub context. This UUID
 * is visible to other clients via the here_now call and is normally
 * autogenerated randomly during pubnub_init(). */
const char *pubnub_current_uuid(struct pubnub *p);

/* Set the UUID of this PubNub context that is asserted during the
 * subscribe call to identify us. This replaces the autogenerated
 * UUID. */
void pubnub_set_uuid(struct pubnub *p, const char *uuid);

/* This function selects the value of CURLOPT_NOSIGNAL which involves
 * a tradeoff:
 *
 * (i) nosignal is true (DEFAULT) - the library is thread safe and does
 * not modify signal handlers, however timeout handling will be broken
 * with regards to DNS requests
 *
 * (ii) nosignal is false - DNS requests will be timing out properly,
 * but the library will install custom SIGPIPE (and possibly SIGCHLD)
 * handlers and won't be thread safe */
void pubnub_set_nosignal(struct pubnub *p, bool nosignal);

/* Set PubNub error retry policy regarding error handling.
 *
 * The call may be retried if the error is possibly recoverable
 * and retry is enabled for that error. This is controlled by
 * @retry_mask; if PNR_xxx-th bit is set, the call is retried in case
 * of the PNR_xxx result; this is the case for recoverable errors,
 * specifically PNR_OK, PNR_OCCUPIED and PNR_CANCELLED bits are always
 * ignored (this may be further extended in the future). For example,
 *
 * 	pubnub_error_policy(p, 0, ...);
 * will turn off automatic error retry for all errors,
 *
 * 	pubnub_error_policy(p, ~0, ...);
 * will turn it on for all recoverable errors (this is the DEFAULT),
 *
 * 	pubnub_error_policy(p, ~(1<<PNR_TIMEOUT), ...);
 * will turn it on for all errors *except* PNR_TIMEOUT, and so on.
 *
 * If the call is not automatically retried after an error, the error
 * is reported to the application via its specified callback instead
 * (if you use the pubnub_sync frontend, it can be obtained from
 * pubnub_last_result(); for future compatibility, you should ideally
 * check it even when relying on automatic error retry).
 *
 * A message about the error is printed on stderr if @print is true
 * (the DEFAULT); this applies even to errors after which we do not
 * retry for whatever reason. */
void pubnub_error_policy(struct pubnub *p, unsigned int retry_mask, bool print);


/** PubNub API requests */

/* All the API request functions accept the @timeout [s] parameter
 * and callback parameters @cb and @cb_data.
 *
 * The @timeout [s] parameter describes how long to wait for request
 * fulfillment before the PNR_TIMEOUT error is generated. Supply -1
 * if in doubt to obtain the optimal default value. (Note that normally,
 * PNR_TIMEOUT will just print a message and retry the request; see
 * pubnub_error_policy() above.)
 *
 * If you are using the pubnub_sync frontend, the function calls
 * will block until the request is fulfilled and you should pass
 * NULL for @cb and @cb_data. If you are using the pubnub_libevent
 * or a custom frontend, the function calls will return immediately
 * and @cb shall point to a function that will be called upon
 * completion (with @cb_data as its last parameter). */

/* For pointer parameters like @channel, @channels or @message (though
 * obviously not @p or @cb_data), no assumption is made regarding their
 * memory lifetime; the pointers may be released by the caller right
 * after the function call. */

/* Publish the @message JSON object on @channel. The response
 * will usually be just a success confirmation. */
void pubnub_publish(struct pubnub *p, const char *channel,
		struct json_object *message,
		long timeout, pubnub_publish_cb cb, void *cb_data);

/* Subscribe to @channel, in addition to the currently subscribed channels.
 *
 * The response will be a JSON array with one received message per item.
 * Messages published on the currently subscribed channels since the
 * last subscribe call are returned.  The response will contain
 * received messages from any of subscribed channels; use the channels
 * callback parameter (or pubnub_sync_last_channels()) to determine
 * the originating channel of each message.
 *
 * In other words, this function does two things - (i) adds @channel
 * to the set of subscribed channels, if not already there; (ii) ask for
 * new messages appearing in the whole set of currently subscribed channels,
 * calling the callback when some arrive.  If you would like to do just
 * (ii), you can also pass NULL as @channel.
 *
 * The first call will typically just establish the context and return
 * immediately with an empty response array. Usually, you would issue
 * the subscribe request in a loop. */
void pubnub_subscribe(struct pubnub *p, const char *channel,
		long timeout, pubnub_subscribe_cb cb, void *cb_data);

/* Subscribe to a set of @channels (in addition to already subscribed
 * channels) all at once. */
void pubnub_subscribe_multi(struct pubnub *p, const char *channels[], int channels_n,
		long timeout, pubnub_subscribe_cb cb, void *cb_data);

/* Cancel an ongoing subscription to @channels.  If a subscribe is
 * currently ongoing, it will be restarted silently (without subscribe
 * callback invoked) to reflect the reduced set of channels.  You can
 * use NULL as a shorthand to unsubscribe from all channels.
 *
 * If no channels remain in the subscription set, the subscribe callback
 * is invoked with PNR_CANCELLED result.
 *
 * This cancellation involves an HTTP notification call, which is
 * what the @timeout parameter pertains to.  Then, a resubscription
 * (if applicable) is issued and @cb called. */
void pubnub_unsubscribe(struct pubnub *p, const char *channels[], int channels_n,
		long timeout, pubnub_unsubscribe_cb cb, void *cb_data);

/* List the last @limit messages that appeared on a @channel.
 * You do not need to be subscribed to the channel. The response
 * will be a JSON array with one message per item. */
void pubnub_history(struct pubnub *p, const char *channel, int limit,
		long timeout, pubnub_history_cb cb, void *cb_data);

/* List the clients subscribed to @channel. The response will be
 * a JSON object with attributes "occupancy" (number of clients)
 * and "uuids" (array of client UUIDs). */
void pubnub_here_now(struct pubnub *p, const char *channel,
		long timeout, pubnub_here_now_cb cb, void *cb_data);

/* Retrieve the server timestamp (number of microseconds since
 * 1970-01-01), stored as JSON value in the response. You can use
 * this as a sort of "ping" message e.g. to estimate network lag,
 * or if you do not trust the system time. */
void pubnub_time(struct pubnub *p, long timeout, pubnub_time_cb cb, void *cb_data);

#ifdef __cplusplus
}
#endif

#endif
