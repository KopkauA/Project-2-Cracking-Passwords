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

/*
Group: Group #16
Members: Aubrey Kopkau (U12459434), Chloe Robinson (U17294327), [Name 3 (UID)], [Name 4 (UID)]
Description: Modification of hash.c to improve password cracking performance while preserving correct output and original password and algorithm ordering. 
Improvements made include:
    Computing MD5, SHA1, SHA256 and SHA512 concurrently across password recordings
    Storing first 16B in binary form avoiding hexadecimal string conversion
    Using hash table to optimize hash comparison
    Replace sprintf with memcompare for hash table look up
    Preserving the original password and algorithm order to ensure the output remains correct.
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
#define MAX_WORKERS 11 // 11 workers + 1 main threads to calculate hash passwords
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
    char *password;
    const char *alg;
    size_t found_idx;           // Password index to enforce first-occurrence rule
    pthread_mutex_t lock;       // Per-target entry lock
};

typedef unsigned char * (*hashing)(unsigned char *, unsigned int);

static const int n_algs = 4;
static hashing fn[4] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
static char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"};

struct worker_data {
    char (*passwords)[256];
    size_t count;
    size_t next_idx;
    pthread_mutex_t queue_mutex;

    struct cracked_hash *cracked;
    int n_hashed;
    size_t *heads;
    size_t *next;

    int remaining_unfound;
    pthread_mutex_t count_mutex;
};

static void *hash_worker(void *arg) {
    struct worker_data *data = (struct worker_data *)arg;

    while (1) {
        // Early exit: stop immediately if all targets have been solved
        pthread_mutex_lock(&data->count_mutex);
        if (data->remaining_unfound <= 0) {
            pthread_mutex_unlock(&data->count_mutex);
            break;
        }
        pthread_mutex_unlock(&data->count_mutex);

        // Dynamically claim next batch of passwords
        pthread_mutex_lock(&data->queue_mutex);
        if (data->next_idx >= data->count) {
            pthread_mutex_unlock(&data->queue_mutex);
            break;
        }

        size_t start = data->next_idx;
        size_t end = start + CHUNK_SIZE;
        if (end > data->count) {
            end = data->count;
        }
        data->next_idx = end;
        pthread_mutex_unlock(&data->queue_mutex);

        // Compute hash and check table immediately in parallel
        for (size_t index = start; index < end; index++) {
            char *pwd = data->passwords[index];
            unsigned int len = (unsigned int)strlen(pwd);

            for (int i = 0; i < n_algs; i++) {
                unsigned char *hash = fn[i]((unsigned char *)pwd, len);
                if (!hash) continue;

                size_t b = hash_bin(hash);

                for (size_t j = data->heads[b]; j != (size_t)-1; j = data->next[j]) {
                    struct cracked_hash *target = &data->cracked[j];

                    if (memcmp(hash, target->bin_hash, KEEP) == 0) {
                        pthread_mutex_lock(&target->lock);
                        if (target->password == NULL) {
                            target->password = strdup(pwd);
                            target->alg = algs[i];
                            target->found_idx = index;

                            pthread_mutex_lock(&data->count_mutex);
                            data->remaining_unfound--;
                            pthread_mutex_unlock(&data->count_mutex);
                        } else if (index < target->found_idx) {
                            // Enforce first-occurrence rule if chunks completed out of order
                            free(target->password);
                            target->password = strdup(pwd);
                            target->alg = algs[i];
                            target->found_idx = index;
                        }
                        pthread_mutex_unlock(&target->lock);
                    }
                }

                free(hash);
            }
        }
    }

    return NULL;
}

///MODIFIED FUNCTION TO USE 11 THREADS///
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
	fp = fopen(hashed_list, "r");
	assert(fp != NULL);
	while(fscanf(fp, "%255s", hex_hash) == 1)
		n_hashed++;
	rewind(fp);

    struct cracked_hash *cracked_hashes = malloc(n_hashed * sizeof(struct cracked_hash));	assert(n_hashed == 0 || cracked_hashes != NULL);
	for (int i = 0; i < n_hashed; i++) {
        fscanf(fp, "%255s", hex_hash);
        hex_to_bin(hex_hash, cracked_hashes[i].bin_hash);
        cracked_hashes[i].password = NULL;
        cracked_hashes[i].alg = NULL;
        cracked_hashes[i].found_idx = (size_t)-1;
        pthread_mutex_init(&cracked_hashes[i].lock, NULL);
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
    size_t count = 0, capacity = 4096;
    char (*passwords)[256] = malloc(capacity * sizeof(*passwords));
    assert(passwords != NULL);

    fp = fopen(password_list, "r");
    assert(fp != NULL);

    while (fscanf(fp, "%255s", passwords[count]) == 1) {
        count++;
        if (count == capacity) {
            capacity *= 2;
            char (*tmp)[256] = realloc(passwords, capacity * sizeof(*passwords));
            assert(tmp != NULL);
            passwords = tmp;
        }
    }
    fclose(fp);

    /* Hash passwords concurrently: at most 9 threads in total. */
    struct worker_data data = {
        .passwords = passwords,
        .count = count,
        .next_idx = 0,
        .cracked = cracked_hashes,
        .n_hashed = n_hashed,
        .heads = heads,
        .next = next,
        .remaining_unfound = n_hashed
    };

    pthread_mutex_init(&data.queue_mutex, NULL);
    pthread_mutex_init(&data.count_mutex, NULL);

    pthread_t threads[MAX_WORKERS];
    int created = 0;

    for (int i = 0; i < MAX_WORKERS && (size_t)i < count; i++) {
        if (pthread_create(&threads[created], NULL, hash_worker, &data) != 0)
            break;
        created++;
    }

    /* Main thread helps process remaining passwords. */
    hash_worker(&data);

    for (int i = 0; i < created; i++)
        pthread_join(threads[i], NULL);

	// print results
    fp = fopen(output, "w");
    assert(fp != NULL);
    for (int i = 0; i < n_hashed; i++) {
        if (cracked_hashes[i].password == NULL)
            fprintf(fp, "not found\n");
        else
            fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
    }
    fclose(fp);
	
	//Free resources
    pthread_mutex_destroy(&data.queue_mutex);
    pthread_mutex_destroy(&data.count_mutex);

    for (int i = 0; i < n_hashed; i++) {
        free(cracked_hashes[i].password);
        pthread_mutex_destroy(&cracked_hashes[i].lock);
    }

    free(next);
    free(heads);
    free(passwords);
    free(cracked_hashes);
}

