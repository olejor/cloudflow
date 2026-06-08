#include <stdatomic.h>


static volatile atomic_bool stop;
static volatile atomic_int stop_code;


int stop_notified(void)
{
	return stop;
}

/* safe to use from signal handler */
void stop_signal(int sig)
{
	(void)sig;

	atomic_store(&stop, 1);
}

/* safe to use from threads */
void stop_notify(int code)
{
	atomic_store(&stop, 1);

	/* store non zero code only (indicates error) */
	if (code)
		atomic_store(&stop_code, code);
}

int stop_code_get(void)
{
	return stop_code;
}
