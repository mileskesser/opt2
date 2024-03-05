#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_BUFFER 1024

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int charToNum(char c) {
    if (c == ' ') return 26; // Space maps to 26
    return c - 'A'; // 'A'-'Z' maps to 0-25
}

char numToChar(int n) {
    if (n == 26) return ' '; // 26 maps back to space
    return 'A' + n; // 0-25 maps back to 'A'-'Z'
}

void customDecrypt(char *ciphertext, char *key, char *plaintext, int text_length) {
    for (int i = 0; i < text_length; i++) {
        int ct_num = charToNum(ciphertext[i]);
        int key_num = charToNum(key[i % strlen(key)]); // Loop key if shorter than plaintext
        int pt_num = (ct_num - key_num + 27) % 27; // Add 27 to ensure the result is not negative
        plaintext[i] = numToChar(pt_num);
    }
    plaintext[text_length] = '\0'; // Null-terminate the plaintext
}

void setupAddressStruct(struct sockaddr_in* address, int portNumber) {
    memset((char*) address, '\0', sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);
    address->sin_addr.s_addr = INADDR_ANY;
}

void handleConnection(int connectionSocket) {
    char buffer[MAX_BUFFER];
    memset(buffer, '\0', MAX_BUFFER);
    
    int charsRead = recv(connectionSocket, buffer, MAX_BUFFER - 1, 0);
    if (charsRead < 0) error("ERROR reading from socket");
    
    char *ciphertext = strtok(buffer, "\n");
    char *key = strtok(NULL, "\n");
    if (ciphertext == NULL || key == NULL) error("ERROR parsing ciphertext or key");

    char plaintext[MAX_BUFFER];
    customDecrypt(ciphertext, key, plaintext, strlen(ciphertext));

    int charsWritten = send(connectionSocket, plaintext, strlen(plaintext), 0);
    if (charsWritten < 0) error("ERROR writing to socket");

    close(connectionSocket);
}

int main(int argc, char *argv[]) {
    int listenSocket, connectionSocket;
    struct sockaddr_in serverAddress, clientAddress;
    socklen_t sizeOfClientInfo = sizeof(clientAddress);

    if (argc < 2) {
        fprintf(stderr,"USAGE: %s port\n", argv[0]);
        exit(1);
    }

    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0) error("ERROR opening socket");

    setupAddressStruct(&serverAddress, atoi(argv[1]));

    if (bind(listenSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) error("ERROR on binding");

    listen(listenSocket, 5);

    while (1) {
        connectionSocket = accept(listenSocket, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);
        if (connectionSocket < 0) error("ERROR on accept");

        int pid = fork();
        if (pid < 0) error("ERROR on fork");
        if (pid == 0) {
            close(listenSocket);
            handleConnection(connectionSocket);
            exit(0);
        } else {
            close(connectionSocket);
            
        }
    }

    close(listenSocket);
    return 0;
}

