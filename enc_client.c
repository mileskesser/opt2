
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define BUFFER_SIZE 1024

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int readFile(const char *filename, char **buffer) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Could not open file %s\n", filename);
        exit(1);
    }

    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);

    *buffer = malloc(length + 1);
    if (!*buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    fread(*buffer, 1, length, f);
    fclose(f);
    (*buffer)[length] = '\0';

    return length;
}

int main(int argc, char *argv[]) {
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    char *plaintext;
    char *key;
    char buffer[BUFFER_SIZE];

    if (argc < 4) {
       fprintf(stderr,"usage %s plaintext key port\n", argv[0]);
       exit(0);
    }

    portno = atoi(argv[3]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    server = gethostbyname("localhost");
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);

    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");

    // Read plaintext and key from files
    int plaintextLength = readFile(argv[1], &plaintext);
    int keyLength = readFile(argv[2], &key);

    // Validate key length
    if (keyLength < plaintextLength) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        exit(1);
    }

    // Send plaintext and key to server
    n = write(sockfd, plaintext, strlen(plaintext));
    if (n < 0) error("ERROR writing to socket");
    n = write(sockfd, key, strlen(key));
    if (n < 0) error("ERROR writing to socket");

    // Read ciphertext back from server
    bzero(buffer, BUFFER_SIZE);
    n = read(sockfd, buffer, BUFFER_SIZE-1);
    if (n < 0) error("ERROR reading from socket");

    printf("%s\n", buffer);

    close(sockfd);
    free(plaintext);
    free(key);
    return 0;
}