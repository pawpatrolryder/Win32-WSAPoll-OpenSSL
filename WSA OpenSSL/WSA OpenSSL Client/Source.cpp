#include "common.h"

#define DEFAULT_BUFLEN 256

int sendall(SSL* ssl, const char* buf, int* len)
{
	int total = 0;        // how many bytes we've sent
	int bytesleft = *len; // how many we have left to send
	int n;

	while (total < *len) {
		n = SSL_write(ssl, buf + total, bytesleft);
		if (n == -1) { break; }
		total += n;
		bytesleft -= n;
	}

	*len = total; // return number actually sent here

	return n == -1 ? -1 : 0; // return -1 on failure, 0 on success
}

SSL_CTX* InitCtx(void) {
	const SSL_METHOD* method;
	SSL_CTX* ctx;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = SSLv23_method();
	ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		std::cerr << "[-] Unable to creat SSL context!";
		abort();
	}
	return ctx;
}

int main(void) {
	SSL_CTX* ctx;
	SSL* ssl;

	WSADATA wsaData;

	int bytes;
	int len;
	const char* host = "127.0.0.1";
	unsigned short int port = 4444;
	char recvbuf[DEFAULT_BUFLEN];

	SSL_library_init();

	ctx = InitCtx();

	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		std::cerr << "WSAStartup Failed with error: " << iResult << std::endl;
		return 1;
	}

	SOCKET sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == INVALID_SOCKET)
	{
		std::cerr << "[-] Can't create a socket! Quitting...";
		WSACleanup();
		return 1;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, host, &(addr.sin_addr)) <= 0) {
		std::cerr << "[-] inet_pton failed! Quitting...";
		WSACleanup();
		return 1;
	}

	if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		std::cerr << "[-] Failed to connect to server! Quitting...";
		WSACleanup();
		return 1;
	}
	else
	{
		std::cout << "[+] Connected to server\n";
	}

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockfd);

	if (SSL_connect(ssl) != 1) {
		std::cout << "[-] SSL Handshake failed!";
		ERR_print_errors_fp(stderr);
		return 1;
	}
	else {
		const char* msg = "Hello from client!\n";
		len = strlen(msg);

		printf("[+] Connection established with %s encryption\n", SSL_get_cipher(ssl));
		if (sendall(ssl, msg, &len) == -1) {
			printf("[-] Error sending\n");
		}
		else {
			printf("[+] Sent server %d bytes\n", len);
		}
		do {
			ZeroMemory(recvbuf, DEFAULT_BUFLEN);
			bytes = SSL_read(ssl, recvbuf, DEFAULT_BUFLEN - 1);

			if (bytes > 0) {
				printf("%s", recvbuf); //If you ever want to see the multiple reads in action put a \n within the printf function.
				continue;
			}
			else if (bytes == 0) {
				break;
			}
			else {
				ERR_print_errors_fp(stderr);
			}
		} while (bytes != 19);
	}

	const char* secondmsg = "The first thing for you to understand is that in this place there are no martyrdoms. You have read of the religious persecutions of the past. In the Middle Ages there was the Inquisitlon. It was a failure. It set out to eradicate heresy, and ended by perpetuating it. For every heretic it burned at the stake, thousands of others rose up. Why was that? Because the Inquisition killed its enemies in the open, and killed them while they were still unrepentant: in fact, it killed them because they were unrepentant. Men were dying because they would not abandon their true beliefs. Naturally all the glory belonged to the victim and all the shame to the Inquisitor who burned him. Later, in the twentieth century, there were the totalitarians, as they were called. There were the German Nazis and the Russian Communists. The Russians persecuted heresy more cruelly than the Inquisition had done. And they imagined that they had learned from the mistakes of the past; they knew, at any rate, that one must not make martyrs. Before they exposed their victims to public trial, they deliberately set themselves to destroy their dignity. They wore them down by torture and solitude until they were despicable, cringing wretches, confessing whatever was put into their mouths, covering themselves with abuse, accusing and sheltering behind one another, whimpering for mercy. And yet after only a few years the same thing had happened over again. The dead men had become martyrs and their degradation was forgotten. Once again, why was it? In the first place, because the confessions that they had made were obviously extorted and untrue. We do not make mistakes of that kind. All the confessions that are uttered here are true. We make them true. And above all we do not allow the dead to rise up against us. You must stop imagining that posterity will vindicate you, Winston. Posterity will never hear of you. You will be lifted clean out from the stream of history. We shall turn you into gasand pour you into the stratosphere. Nothing will remain of you, not a name in a register, not a memory in a living brain. You will be annihilated in the past as well as in the future. You will never have existed.";
	len = strlen(secondmsg);
	if (sendall(ssl, secondmsg, &len) == -1) {
		printf("[-] Error sending\n");
	}
	else {
		printf("[+] Sent server %d bytes\n", len);
	}

	SSL_free(ssl);
	SSL_CTX_free(ctx);
	closesocket(sockfd);
	if (WSACleanup() == 0) {
		std::cout << "[+] WSACleanup was successful!";
	}
	return 0;
}