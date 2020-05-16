#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <errno.h>
#include <openssl/evp.h>


#define HANDLE_ERROR(msg) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); }
#define HANDLE_ERROR2(msg, mdctx) { fprintf(stderr, "%s\n", msg); EVP_MD_CTX_destroy(mdctx); exit(EXIT_FAILURE); }
#define CHECK_ERR(a,msg) {if ((a) == -1) { perror((msg)); exit(EXIT_FAILURE); } }
#define FILE_SIZE 1024*1024*16

unsigned char * sha3_512(char * addr, unsigned int size, int * result_len_ptr);
unsigned long get_file_size(char * fname);

int main(int argc, char * argv[]) {

	int pipe_fd[2];
	char * cwd = getcwd(NULL, 0);
	char * file_name = "/output.txt";
	unsigned long file_size;
	int res;
	int fd;

	file_name = strcat(cwd, file_name);
	file_size = get_file_size(file_name);

	CHECK_ERR(file_size,"get_file_size()");

	CHECK_ERR(pipe(pipe_fd), "pipe()")

	fd = open(file_name,
			  O_RDONLY,
			  S_IRUSR | S_IWUSR // l'utente proprietario del file avrà i permessi di lettura e scrittura sul nuovo file
			 );

	CHECK_ERR(fd, "open()")

	char * addr = mmap(NULL, // NULL: è il kernel a scegliere l'indirizzo
					FILE_SIZE, // dimensione della memory map
					PROT_READ | PROT_WRITE, // memory map leggibile e scrivibile
					MAP_SHARED | MAP_ANONYMOUS, // memory map condivisibile con altri processi
					-1,
					0); // offset nel file

	if (addr == MAP_FAILED) {
		perror("mmap()");
		exit(EXIT_FAILURE);
	}

	memset(addr, 0xFF, file_size);

	unsigned char * digest;
	int digest_len;

	switch (fork()) {
			case -1:
				perror("fork()");
				exit(EXIT_FAILURE);

			case 0: // processo FIGLIO: legge dalla PIPE

				close(pipe_fd[1]); // chiudiamo l'estremità di scrittura della pipe

				char * child_buffer = malloc(file_size);

				if (child_buffer == NULL) {
					perror("malloc()");
					exit(EXIT_FAILURE);
				}

				// pipe vuota: read() si blocca in attesa di dati
				while ((res = read(pipe_fd[0], child_buffer, file_size)) > 0) {
					printf("[child] received %d bytes from pipe\n", res);
					printf("[child] buffer: %s\n", child_buffer);
					digest = sha3_512(child_buffer, file_size, &digest_len);
					memcpy(addr, digest, digest_len);
				}

				if (res == -1) {
					perror("read()");
				} else {
					printf("[child] EOF on pipe\n");
				}

				//digest = sha3_512(child_buffer, file_size, &digest_len);
				// copy hash to memory map
				//memcpy(addr, digest, digest_len);

				printf("[child] bye\n");

				close(pipe_fd[0]);
				free(child_buffer);

				exit(EXIT_SUCCESS);

			default: // processo PADRE: scrive nella PIPE

				printf("[parent] starting\n");

				close(pipe_fd[0]); // chiudiamo l'estremità di lettura della pipe

				char * parent_buffer = malloc(file_size);

				if (parent_buffer == NULL) {
					perror("malloc()");
					exit(EXIT_FAILURE);
				}

				// leggo dal file e salvo in buffer...
				while (read(fd, parent_buffer, file_size) > 0)

				close(fd);
				// se pipe piena (capacità: 16 pages) allora write() si blocca
				res = write(pipe_fd[1], parent_buffer, file_size);
				CHECK_ERR(res, "write()")

				printf("[parent] %d bytes written to pipe\n", res);

				close(pipe_fd[1]); // chiudiamo estremità di scrittura della pipe
				// dall'altra parte verrà segnalato EOF

				printf("[parent] before wait()\n");

				wait(NULL);

				printf("[parent] SHA3_512 del file %s è il seguente: ", file_name);
				for (int i = 0; i < 512/8; i++) {
					printf("%02x", addr[i]);
				}
				printf("\n[parent] bye\n");

				free(parent_buffer);

				exit(EXIT_SUCCESS);
		}

}

unsigned char * sha3_512(char * addr, unsigned int size, int * result_len_ptr) {

	EVP_MD_CTX * mdctx;
	int val;
	unsigned char * digest;
	unsigned int digest_len;
	EVP_MD * algo = NULL;

	algo = EVP_sha3_512();

	if ((mdctx = EVP_MD_CTX_create()) == NULL) {
		HANDLE_ERROR("EVP_MD_CTX_create() error")
	}

	// initialize digest engine
	if (EVP_DigestInit_ex(mdctx, algo, NULL) != 1) { // returns 1 if successful
		HANDLE_ERROR2("EVP_DigestInit_ex() error", mdctx)
	}

	// provide data to digest engine
	if (EVP_DigestUpdate(mdctx, addr, size) != 1) { // returns 1 if successful
		HANDLE_ERROR2("EVP_DigestUpdate() error", mdctx)
	}

	digest_len = EVP_MD_size(algo); // sha3_512 returns a 512 bit hash

	if ((digest = (unsigned char *)OPENSSL_malloc(digest_len)) == NULL) {
		HANDLE_ERROR2("OPENSSL_malloc() error", mdctx)
	}

	// produce digest
	if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) { // returns 1 if successful
		OPENSSL_free(digest);
		HANDLE_ERROR2("EVP_DigestFinal_ex() error", mdctx)
	}

	unsigned char * result = malloc(digest_len);
	if (result == NULL) {
		perror("malloc()");
		exit(EXIT_FAILURE);
	}

	memcpy(result, digest, digest_len);

	*result_len_ptr = digest_len;

	OPENSSL_free(digest);
	EVP_MD_CTX_destroy(mdctx);

	return result;
}

unsigned long get_file_size(char * fname) {

	struct stat st;

	int res = stat(fname, &st);

	if (res == -1) {
		perror("stat error");
		return -1;
	} else
		return st.st_size;

}
