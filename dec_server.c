#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

void error(const char *msg) {
    perror(msg);
    exit(1);
}

void otp_encrypt_decrypt(char *text, char *key, char *result, int length, int encrypt) {
    for (int i = 0; i < length; ++i) {
        int textVal = (text[i] == ' ') ? 26 : text[i] - 'A';
        int keyVal = (key[i] == ' ') ? 26 : key[i] - 'A';
        int resultVal = encrypt ? (textVal + keyVal) % 27 : (textVal - keyVal + 27) % 27;
        result[i] = (resultVal == 26) ? ' ' : 'A' + resultVal;
    }
    result[length] = '\0';
}

void handleConnection(int sock) {
    char ciphertext[256], key[256], plaintext[256];
    bzero(ciphertext, 256);
    bzero(key, 256);

    // Read ciphertext from client
    int n = read(sock, ciphertext, 255);
    if (n < 0) error("ERROR reading from socket");
    
    // Read key from client
    n = read(sock, key, 255);
    if (n < 0) error("ERROR reading from socket");

    // Perform decryption
    otp_encrypt_decrypt(ciphertext, key, plaintext, strlen(ciphertext), 0); // 0 for decryption

    // Send plaintext back to client
    n = write(sock, plaintext, strlen(plaintext));
    if (n < 0) error("ERROR writing to socket");

    close(sock);
}

int main(int argc, char *argv[]) {
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;

    if (argc < 2) {
        fprintf(stderr, "ERROR, no port provided\n");
        exit(1);
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");
    
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
        error("ERROR on binding");
    
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    while (1) {
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) 
            error("ERROR on accept");
        
        int pid = fork();
        if (pid < 0)
            error("ERROR on fork");
        if (pid == 0) {
            close(sockfd);
            handleConnection(newsockfd);
            exit(0);
        } else {
            close(newsockfd);
        }
    }

    close(sockfd);
    return 0; 
}