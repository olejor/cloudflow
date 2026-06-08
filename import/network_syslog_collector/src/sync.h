#ifndef __SYNC_H__
#define __SYNC_H__

/* check if stop was notified */
int stop_notified(void);

/* notify stop from signal handler */
void stop_signal(int sig);

/* notify stop from thread context */
void stop_notify(int code);

/* get notified stop code */
int stop_code_get(void);

#endif
