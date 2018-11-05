#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>

static const char passchars[] = "abcdefghikjlmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+\"#&/()=?!@$|[]|{}";
static const int passcharCount = strlen(passchars);
static const int maxPasswordLength= 30;
static const int normalHashLength= 34;
int crackByBruteforce(char * password, char * salt, char * hash, int charPos) {
	for(int i = -1; i < passcharCount; i++) {
		if(i != -1) {
			*(password + charPos) = passchars[i];
		}
		if(charPos > 0) {
			if(crackByBruteforce(password, salt, hash, charPos - 1) == 1) {
				return 1;
			}
		}
		else if(charPos == 0) {
			printf("%s\n", password);
			char * test = crypt(password, salt);
			if(strncmp(test, hash, normalHashLength) == 0) {
				printf("Password \"%s\"\n", password);
				return 1;
			}
		}
	}
	return 0;
}
int crackByDictionary(char * password, char * salt, char * hash) {
	FILE * file = fopen("dictionary.txt", "r");
	int successStatus = 0;
	while(!feof(file)) {
		fgets(password, maxPasswordLength, file);
		for(int i = 0; i < maxPasswordLength; i++) {
			if(*(password + i) == '\n') {
				*(password + i) = '\0';
			}
		}
		printf("%s\n", password);
		char * test = crypt(password, salt);
		if(strncmp(test, hash, normalHashLength) == 0) {
			printf("Password \"%s\"\n", password);
			successStatus = 1;
			break;
		}
	}
	fclose(file);
	return successStatus;
}
int main (int argc, char * argv[]) {
	if(argc != 2) {
		return -1;
	}
	char * hash = argv[1];
	char salt[13] ;
	strncpy(salt, hash, 12);
	char * password = (char *)malloc(sizeof(char) * maxPasswordLength);
	if(crackByDictionary(password, salt, hash) == 0) {
		for(int i = 0; i < maxPasswordLength; i++) {
			*(password + i) = '\0';
		}
		if(crackByBruteforce(password, salt, hash, maxPasswordLength - 1) == 0) {
			printf("Failed\n");
		}
	}
	free(password);
	return 0;
}
