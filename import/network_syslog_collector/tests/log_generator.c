// Integration test for Logchewie. Application generates syslog messages
// with random facility, random severity and random meeage text

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <syslog.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT "514"
#define BUFFER_SIZE 1024

static const int facility[] = {LOG_KERN, LOG_USER, LOG_MAIL, LOG_DAEMON,
        LOG_AUTH, LOG_SYSLOG, LOG_LPR, LOG_NEWS, LOG_UUCP, LOG_CRON,
        LOG_AUTHPRIV, LOG_FTP, LOG_LOCAL0, LOG_LOCAL1, LOG_LOCAL2,
        LOG_LOCAL3, LOG_LOCAL4, LOG_LOCAL5, LOG_LOCAL6, LOG_LOCAL7};

static const int severity[] = {LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR,
        LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG};

static const char *log[] = {
    "1 Receive syslog messages: The program must receive large volumes of syslog messages over UDP.",
    "2 Filter syslog messages: The application will filter messages based on configurable priority, facility, and text patterns.",
    "3 Forward filtered messages: Relevant messages will be sent to specific Redis streams for further processing or alerting.",
    "4 Redis Cluster Integration: The application will seamlessly integrate with Redis to send filtered messages to specified streams.",
    "5 Concurrency with Event Loop and Threads: The application must use an event loop to manage UDP message reception and support multiple worker threads for concurrent processing and forwarding."
};

// Generates log, remember to free buffer after usage.
char *generate_log()
{
    char *buffer = (char *)malloc(BUFFER_SIZE * sizeof(char) + 1);
    if (buffer != NULL) {
        snprintf(buffer, BUFFER_SIZE, "<%d> %s",
        LOG_MAKEPRI(facility[(rand() % 20)], severity[(rand() % 8)]), log[(rand() % 5)]);
    }

    return buffer;
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    const char *server_ip;
    const char *server_port;
    char *buffer = NULL;

    server_ip = getenv("SERVER_IP");
    if (!server_ip)
        server_ip = SERVER_IP;

    server_port = getenv("SERVER_PORT");
    if (!server_port)
        server_port = SERVER_PORT;

    srand(time(0));

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0x00, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(atoi(server_port));
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    while (1) {
        buffer = generate_log();
        if (sendto(sockfd, buffer, strlen(buffer), 0, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Send message error");
            close(sockfd);
            free(buffer);
            exit(EXIT_FAILURE);
        }
        usleep(1);
    }

    free(buffer);
    close(sockfd);
    return 0;
}
