#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define MAX_BUFFER 1024

void error(const char *msg) {
    perror(msg);
    exit(0);
}

void setupAddressStruct(struct sockaddr_in* address, int portNumber, char* hostname) {
    memset((char*) address, '\0', sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);
    struct hostent* hostInfo = gethostbyname(hostname);
    if (hostInfo == NULL) {
        fprintf(stderr, "CLIENT: ERROR, no such host\n");
        exit(0);
    }
    memcpy((char*)&address->sin_addr.s_addr, hostInfo->h_addr_list[0], hostInfo->h_length);
}

int main(int argc, char *argv[]) {
    int socketFD, portNumber, charsWritten, charsRead;
    struct sockaddr_in serverAddress;
    char buffer[MAX_BUFFER];


    if (argc < 5) {
        fprintf(stderr,"USAGE: %s hostname port plaintext key\n", argv[0]);
        exit(0);
    }

    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) error("CLIENT: ERROR opening socket");

    setupAddressStruct(&serverAddress, atoi(argv[2]), argv[1]);

    if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) error("CLIENT: ERROR connecting");

    // Read plaintext from file
    FILE *plaintextFile = fopen(argv[3], "r");
    if (plaintextFile == NULL) error("ERROR opening plaintext file");
    fgets(buffer, MAX_BUFFER - 1, plaintextFile);
    fclose(plaintextFile);
    buffer[strcspn(buffer, "\n")] = '\0'; // Remove newline

    // Append key to the buffer separated by a newline
    strcat(buffer, "\n");
    strcat(buffer, argv[4]);

    // Send plaintext and key to server
    charsWritten = send(socketFD, buffer, strlen(buffer), 0); 
    if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
    if (charsWritten < strlen(buffer)) printf("CLIENT: WARNING: Not all data written to socket!\n");


    // Receive ciphertext from server
    memset(buffer, '\0', sizeof(buffer));
    charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); 
    if (charsRead < 0) error("CLIENT: ERROR reading from socket");
    printf("Ciphertext: %s\n", buffer);

    close(socketFD); // Close the socket
    return 0;
}
