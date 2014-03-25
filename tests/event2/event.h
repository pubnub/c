#ifndef EVENT2_H
#define EVENT2_H

struct event {
	int unused;
};

#define EV_READ 1
#define EV_WRITE 2
#define EV_PERSIST 4

#define evtimer_new(b, cb, arg)	       event_new((b), -1, 0, (cb), (arg))

#endif // EVENT2_H