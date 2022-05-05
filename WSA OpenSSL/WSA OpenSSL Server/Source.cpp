#include "common.h"

#define DEFAULT_BUFLEN 256

static bool running = true;

int sendall(SSL* ssl, const char* buf, int* len)
{
	int total = 0;        // how many bytes we've sent
	int bytesleft = *len; // how many we have left to send
	int n;

	while (total < *len) {
		n = SSL_write(ssl, buf + total, bytesleft);
		if (n <= 0) { break; }
		total += n;
		bytesleft -= n;
	}

	*len = total; // return number actually sent here

	return n == -1 ? -1 : 0; // return -1 on failure, 0 on success
}

BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType)
{
	switch (dwCtrlType)
	{
	case CTRL_C_EVENT:
		running = false;
		break;
	}
	return TRUE;
}

void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile) {
	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		std::cerr << "[-] Private key does not match the public certificate";
		ERR_print_errors_fp(stderr);
		abort();
	}
	else {
		std::cout << "[+] Certificate and private key loaded and verified\n\n";
	}
}

SSL_CTX* InitServerCTX(void) {
	SSL_CTX* ctx = NULL;
	const SSL_METHOD* method;

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	method = SSLv23_method();
	ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		std::cerr << "[-] Unable to creat SSL context!";
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

int main(void) {
	SSL_CTX* ctx;
	SSL* ssl = NULL;

	const char* host = "127.0.0.1";
	unsigned short int port = 4444;
	const unsigned short int clientMaxCount = 3;
	static unsigned short int numfds = 0;

	SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

	WSADATA wsaData;
	WSAPOLLFD fdArray[clientMaxCount];
	memset(&fdArray, 0, sizeof(fdArray));

	SSL_library_init();

	ctx = InitServerCTX();
	LoadCertificates(ctx, "server.crt", "server.key"); //You will need to change\add the directory\file names to corretly point to the certificate and key.

	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		std::cerr << "[-] WSAStartup failed with error #: " << iResult << std::endl;
		return 1;
	}

	SOCKET servfd = socket(AF_INET, SOCK_STREAM, 0);
	if (servfd == INVALID_SOCKET)
	{
		std::cerr << "[-] Can't create a socket! Quitting...";
		return 1;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	unsigned short int optval = 1;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, host, &(addr.sin_addr)) <= 0) {
		std::cerr << "[-] inet_pton failed! Quitting...";
		return 1;
	}

	setsockopt(servfd, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));

	if (bind(servfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		std::cerr << "[-] Can't bind port! Quitting...";
		return 1;
	}

	if (listen(servfd, 10) != 0) {
		std::cerr << "[-] Can't configure listening port! Quitting...";
		return 1;
	}

	fdArray[0].fd = servfd;
	fdArray[0].events = POLLRDNORM;
	numfds++;

	while (running) {
		int bytes;
		char recvbuf[DEFAULT_BUFLEN];

		char* buffer = NULL;
		unsigned long LEN = DEFAULT_BUFLEN;
		unsigned long bytes_received = 0;
		unsigned long cur_size = 0;
		int status = 0;

		const char* msg = "Hello from server!\n";
		int lenmsg = strlen(msg);

		int nResult = WSAPoll(fdArray, clientMaxCount, 500);
		if (nResult < 0) {
			std::cerr << "[-] WSAPoll failed! Qutting...";
			return 1;
		}
		else if (nResult == 0) {
			continue;
		}

		for (int fd_index = 0; fd_index < clientMaxCount; fd_index++) {
			if (fdArray[fd_index].revents & POLLRDNORM) {
				if (fdArray[fd_index].fd == servfd) {
					struct sockaddr_in addr;
					socklen_t len = sizeof(addr);

					SOCKET client = accept(servfd, (struct sockaddr*)&addr, &len);
					fdArray[numfds].fd = client;
					fdArray[numfds].revents = POLLRDNORM;

					printf("[+] Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
					ssl = SSL_new(ctx);
					SSL_set_fd(ssl, fdArray[numfds].fd);

					if (SSL_accept(ssl) != 1) {
						std::cout << "[-] SSL Handshake failed!";
						ERR_print_errors_fp(stderr);
					}
					else {
						do {
							ZeroMemory(recvbuf, DEFAULT_BUFLEN);
							bytes = SSL_read(ssl, recvbuf, DEFAULT_BUFLEN - 1);

							if (bytes > 0) {
								printf("%s", recvbuf);
								continue;
							}
							else if (bytes == 0) {
								break;
							}
							else {
								ERR_print_errors_fp(stderr);
							}
						} while (bytes != 19);

						if (sendall(ssl, msg, &lenmsg) == -1) {
							printf("[-] Error sending\n");
						}
						else {
							printf("[+] Sent client %d bytes\n", lenmsg);
						}
						numfds++;
					}
				}
				else {
					do {
						if (bytes_received >= cur_size) {
							char* tmp;
							cur_size += LEN;
							tmp = (char*)realloc(buffer, cur_size);
							if (!tmp) {
								fprintf(stderr, "realloc error=%d\n", WSAGetLastError());
								free(buffer);
								break;
							}
							buffer = tmp;
						}

						status = SSL_read(ssl, buffer + bytes_received, LEN);
						if (status > 0) {
							bytes_received += status;
							continue;
						}
						else if (status == 0) {
							break;
						}
						else {
							fprintf(stderr, "socket error=%d\n", WSAGetLastError());
						}

					} while (status > 0);

					if (bytes_received > 0) {
						buffer[bytes_received] = '\0';
						printf("[+] Received %d bytes\n", bytes_received);
						printf("%s\n", buffer);
					}
				}
			}
			else if (fdArray[fd_index].revents & POLLHUP) {
				closesocket(fdArray[fd_index].fd);
				for (int i = fd_index; i < numfds; i++) {
					fdArray[i] = fdArray[i + 1];
				}
				numfds--;
				printf("\n\n[+] Socket closed\n\n");
			}
		}
	}

	SSL_free(ssl);
	SSL_CTX_free(ctx);
	closesocket(servfd);
	if (WSACleanup() == 0) {
		std::cout << "[+] WSACleanup was successful!";
	}
	return 0;
}