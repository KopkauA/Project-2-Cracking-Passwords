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

#include "hash_functions.h"

//Added allowed libraries
#include <pthread.h>
#include <semaphore.h>

#define KEEP 16 // only the first 16 bytes of a hash are kept

#define MAX_WORKERS 8 // 8 threads to calculate hash passwords
#define HASH_BUCKETS 65536 //

struct cracked_hash {
	char hash[2*KEEP+1];
	char *password, *alg;
};

typedef unsigned char * (*hashing)(unsigned char *, unsigned int);

int n_algs = 4;
hashing fn[4] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"};

//Added
struct password_record {
    char password[256];
    char hashes[4][2 * KEEP + 1];
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

        size_t index = data->next++;
        pthread_mutex_unlock(&data->mutex);

        struct password_record *record = &data->records[index];
        unsigned int len = (unsigned int)strlen(record->password);

        for (int i = 0; i < n_algs; i++) {
            unsigned char *hash = fn[i](
                (unsigned char *)record->password, len
            );

            for (int j = 0; j < KEEP; j++)
                sprintf(&record->hashes[i][2 * j], "%02x", hash[j]);

            record->hashes[i][2 * KEEP] = '\0';
            free(hash);
        }
    }

    return NULL;
}

static size_t hash_key(const char *s) {
    size_t h = 5381;

    for (int i = 0; i < 2 * KEEP; i++)
        h = h * 33 + (unsigned char)s[i];

    return h % HASH_BUCKETS;
}

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
	char hex_hash[2*KEEP+1]; // hashed passwords have at most 'keep' characters

	// load hashed passwords
	int n_hashed = 0;
	struct cracked_hash *cracked_hashes;
	fp = fopen(hashed_list, "r");
	assert(fp != NULL);
	while(fscanf(fp, "%s", hex_hash) == 1)
		n_hashed++;
	rewind(fp);
	cracked_hashes = (struct cracked_hash *) malloc(n_hashed*sizeof(struct cracked_hash));
	assert(n_hashed == 0 || cracked_hashes != NULL);
	for(int i=0; i < n_hashed; i++) {
		fscanf(fp, "%s", cracked_hashes[i].hash);
		cracked_hashes[i].password = NULL;
		cracked_hashes[i].alg = NULL;
	}
	fclose(fp);

	//////////////Modified Section
	// load common passwords, hash them, and compare them to hashed passwords
	/*fp = fopen(password_list, "r");
	assert(fp != NULL);
	while(fscanf(fp, "%s", password) == 1) {

		for(int i=0; i < n_algs; i++) {
			unsigned char *hash = fn[i]((unsigned char *)password, strlen(password));
			for(int j=0; j < KEEP; j++)
				sprintf(&hex_hash[2*j], "%02x", hash[j]);
			hex_hash[2*KEEP] = '\0';
			for(int j=0; j < n_hashed; j++) {
				if(cracked_hashes[j].password !=  NULL)
					continue;
				if(compare_hashes(hex_hash, cracked_hashes[j].hash)) {
					cracked_hashes[j].password = strdup(password);
					cracked_hashes[j].alg = algs[i];
					break;
				}
			}
			free(hash);
		}
	}
	fclose(fp);*/

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
        size_t b = hash_key(cracked_hashes[i].hash);
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
    assert(pthread_mutex_init(&data.mutex, NULL) == 0);

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
            char *digest = records[p].hashes[a];
            size_t b = hash_key(digest);

            for (size_t j = heads[b]; j != (size_t)-1; j = next[j]) {
                if (cracked_hashes[j].password != NULL)
                    continue;

                if (compare_hashes(digest, cracked_hashes[j].hash)) {
                    cracked_hashes[j].password =
                        strdup(records[p].password);
                    assert(cracked_hashes[j].password != NULL);

                    cracked_hashes[j].alg = algs[a];
                    break;
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

