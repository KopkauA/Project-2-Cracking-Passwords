/*

REQUIREMENTS:
- Change the code in the file hash.c to make it faster using threads without changing the correct output. 
- You cannot modify other files (main.c, hash.h, hash_functions.c, hash_functions.h, Makefile). 
- You are only allowed to use:
	1. The pthread and semaphore libraries (and other standard C libraries), 
	2. Your knowledge of algorithms and data structures
	3. Your C coding skills
- Using non-standard libraries, changing compiler flags, and other tricks are not allowed. 
- If, at any point in time, your program has more than 12 threads (including the main thread) in execution, your submission will be deemed invalid. 
- In other words, your process cannot have more than 12 threads running simultaneously.

*/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

//Added allowed libraries
#include <pthread.h>
#include <semaphore.h>

#include "hash_functions.h"

#define KEEP 16 // only the first 16 bytes of a hash are kept
#define MAX_WORKERS 8 // 8 threads to calculate hash passwords
#define HASH_BUCKETS 65536 // 2^16 buckets for hash table
#define CHUNK_SIZE 64 // 64 passwords at once

//ADDED: helper functions for hashing and comparing hashes
/* Helper to convert a single hex character to its 4-bit nibble */
static inline int hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

/* Converts a 32-character hex string into 16 raw binary bytes */
static void hex_to_bin(const char *hex, unsigned char *bin) {
    for (int i = 0; i < KEEP; i++) {
        bin[i] = (unsigned char)((hex_char_to_val(hex[2 * i]) << 4) |
                                 hex_char_to_val(hex[2 * i + 1]));
    }
}

/* Fast bucket indexing: use the first 2 raw bytes (16 bits) directly */
static inline size_t hash_bin(const unsigned char *b) {
    return (((size_t)b[0] << 8) | (size_t)b[1]) % HASH_BUCKETS;
}

struct cracked_hash {
	unsigned char bin_hash[KEEP];
	char *password, *alg;
};

typedef unsigned char * (*hashing)(unsigned char *, unsigned int);

static const int n_algs = 4;
static hashing fn[4] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
static char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"};

//Added
struct password_record {
    char password[256];
    unsigned char hashes[4][KEEP];
};

struct worker_data {
    struct password_record *records;
    size_t count;
    size_t next;
    pthread_mutex_t mutex;
};

static void *hash_worker(void *arg) {
    struct worker_data *data = arg;

    while (1) {
        pthread_mutex_lock(&data->mutex);

        if (data->next >= data->count) {
            pthread_mutex_unlock(&data->mutex);
            break;
        }

        size_t start = data->next;
		size_t end = start + CHUNK_SIZE;
		if (end > data->count){
			end = data->count;
		}

		data->next = end;
        pthread_mutex_unlock(&data->mutex);

		for (size_t index = start; index < end; index++) {

			struct password_record *record = &data->records[index];
			unsigned int len = (unsigned int)strlen(record->password);

			for (int i = 0; i < n_algs; i++) {
				unsigned char *hash = fn[i](
					(unsigned char *)record->password, len
				);

				//copy first 16 bytes directly (no sprintf)
				memcpy(record->hashes[i], hash, KEEP);

				free(hash);
			}
		}
    }

    return NULL;
}

// DEAD CODE: function not being used 10/27 - Aubrey
static size_t hash_key(const char *s) {
    size_t h = 5381;

    for (int i = 0; i < 2 * KEEP; i++)
        h = h * 33 + (unsigned char)s[i];

    return h % HASH_BUCKETS;
}

// DEAD CODE: function not being used 10/27 - Aubrey
int compare_hashes(char *a, char *b) {
	for(int i=0; i < 2*KEEP; i++)
		if(a[i] != b[i])
			return 0;
	return 1;
}

///MODIFIED FUNCTION TO USE 8 THREADS///
// Function name: crack_hashed_passwords
// Description:   Computes different hashes for each password in the password list,
//                then compare them to the hashed passwords to decide whether if
//                any of them matches this password. When multiple passwords match
//                the same hash, only the first one in the list is printed.
void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
	FILE *fp;
	char password[256];  // passwords have at most 255 characters
	char hex_hash[256]; // hashed passwords have at most 256 characters

	// load hashed passwords
	int n_hashed = 0;
	struct cracked_hash *cracked_hashes;
	fp = fopen(hashed_list, "r");
	assert(fp != NULL);
	while(fscanf(fp, "%255s", hex_hash) == 1)
		n_hashed++;
	rewind(fp);

	cracked_hashes = (struct cracked_hash *) malloc(n_hashed*sizeof(struct cracked_hash));
	assert(n_hashed == 0 || cracked_hashes != NULL);
	for(int i=0; i < n_hashed; i++) {
		fscanf(fp, "%255s", hex_hash);
		hex_to_bin(hex_hash, cracked_hashes[i].bin_hash);
		cracked_hashes[i].password = NULL;
		cracked_hashes[i].alg = NULL;
	}
	fclose(fp);


	/*Hash Table Mapping Target digest to target indicies
	Chain to preserve duplicate target hashes
	*/
	size_t *heads = malloc(HASH_BUCKETS * sizeof(*heads));
    size_t *next = malloc((size_t)n_hashed * sizeof(*next));

	assert(heads!=NULL);
	assert(n_hashed == 0||next!=NULL);

	for (size_t b = 0; b < HASH_BUCKETS; b++)
        heads[b] = (size_t)-1;

    for (int i = n_hashed - 1; i >= 0; i--) {
        size_t b = hash_bin(cracked_hashes[i].bin_hash);
        next[i] = heads[b];
        heads[b] = (size_t)i;
    }

    /* Load passwords in their original order. */
    size_t count = 0, capacity = 1024;
    struct password_record *records =
        malloc(capacity * sizeof(*records));
    assert(records != NULL);

    fp = fopen(password_list, "r");
    assert(fp != NULL);

    while (fscanf(fp, "%255s", password) == 1) {
        if (count == capacity) {
            capacity *= 2;
            struct password_record *tmp =
                realloc(records, capacity * sizeof(*records));
            assert(tmp != NULL);
            records = tmp;
        }

        strcpy(records[count].password, password);
        count++;
    }
    fclose(fp);

    /* Hash passwords concurrently: at most 9 threads in total. */
    struct worker_data data = {
        .records = records,
        .count = count,
        .next = 0
    };

	// initialize mutex
    int rc = pthread_mutex_init(&data.mutex, NULL);
	assert(rc == 0);
	(void)rc; // stops compiler warning about unused variable

    pthread_t threads[MAX_WORKERS];
    int created = 0;

    for (int i = 0; i < MAX_WORKERS && (size_t)i < count; i++) {
        if (pthread_create(&threads[created], NULL,
                           hash_worker, &data) != 0)
            break;
        created++;
    }

    /* Main thread helps process remaining passwords. */
    hash_worker(&data);

    for (int i = 0; i < created; i++)
        pthread_join(threads[i], NULL);

    pthread_mutex_destroy(&data.mutex);

    /*
     * Match serially in original password and algorithm order.
     * Only matching hash-table buckets are searched.
     */
    for (size_t p = 0; p < count; p++) {
        for (int a = 0; a < n_algs; a++) {
            unsigned char *bin_digest = records[p].hashes[a];

            size_t b = hash_bin(bin_digest);

            for (size_t j = heads[b]; j != (size_t)-1; j = next[j]) {
                if (cracked_hashes[j].password != NULL)
                    continue;

				if (memcmp(bin_digest, cracked_hashes[j].bin_hash, KEEP) == 0) {
                    cracked_hashes[j].password = strdup(records[p].password);
                    assert(cracked_hashes[j].password != NULL);
                    cracked_hashes[j].alg = algs[a];
                }
            }
        }
    }

	// print results
	fp = fopen(output, "w");
	assert(fp != NULL);
	for(int i=0; i < n_hashed; i++) {
		if(cracked_hashes[i].password ==  NULL)
			fprintf(fp, "not found\n");
		else
			fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
	}
	fclose(fp);

	// release stuff
	for(int i=0; i < n_hashed; i++)
		free(cracked_hashes[i].password);
	
	//Free hashes
    free(next);
    free(heads);
    free(records);
	free(cracked_hashes);
}

