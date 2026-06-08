#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "filter.h"

#define MAX_LOG_SIZE 1024

int main(int argc, char **argv) {
	char message[MAX_LOG_SIZE];

	if (filter_init())
		return 1;

	if (argc == 2) {
		int result;
		snprintf(message, MAX_LOG_SIZE, "<30> %s", argv[1]);
		result = filter_match_rules(message, strlen(message), NULL, NULL);
		printf("Result is %d\n", result);
	}

	return 0;
}
