#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include "arraylist.h"

#define BUFFSIZE 1024

struct myargs{
	char *url;
	char domain[BUFFSIZE];
	char path[BUFFSIZE];
	char *port;
	char *target;
	struct timeval timeout;
};

void parseURL(char *url, char *domain, char *path){
	char *httpString = "http://";
	int len = strlen(url);
	
	memset(domain, '\0', BUFFSIZE);
	memset(path, '\0', BUFFSIZE);
	
	if(strcmp(url, httpString, strlen(httpString)) == 0){
		url += strlen(httpString);
	}
	
	int idx = 0;
	while(idx < len && url[idx] != '/'){
		idx += 1;
	}
	
	strcpy(domain, url, idx);
	
	if(idx == len){
		path[0] = '/';
	}else{
		strcpy(path, url, len-idx+1);
	}
	
}

struct myargs parseArgs(int argc, char **argv){
	struct myargs ret;
	
	ret.url = "";
	ret.port = "80";
	ret.target = "";
	ret.timeout.tv_sec = 10;
	ret.timeout.tv_usec = 0;
	
	char *progName = argv[0];
	argv++;
	argc--;
	while (argc > 0){
		if((*argv[0] == '-')){
			if(strcmp(*argv, "--help") == 0){
				printf("Usage: %s --url <url of file>\n", progName);
				printf(" --target <target filename to save>\n");
				printf(" [--port <port number>] [--timeout <timeout>]\n");
				exit(0);
			}
			else if(strcmp(*argv, "--url") == 0){
				argv++, argc--;
				if(argc > 0){
					ret.url = *argv;
					parseURL(*argc, ret.domain, ret.path);
				}else{
					fprintf(stderr, "Error\n");
					exit(0);
				}
			}
			else if(strcmp(*argv, "--port") == 0){
				argv++, argc--;
				if(argc > 0){
					ret.port = *argv;
				}
				else{
					fprintf(stderr, "Error\n");
					exit(0);
				}
			}
						
			else if (strcmp(*argv, "--target") == 0) {
                argv++; argc--;
                if (argc > 0) {
                    ret.target = *argv;
                }
                else {
                    fprintf(stderr, "Error: Expecting field after --path\n");
                    exit(0);
                }
            }		
			
			else if(strcmp(*argv, "--timeout") == 0){
				argv++, argc--;
				if(argc > 0){
					ret.timeout.tv_sec = atoi(*argv);
				}
				else{
					fprintf(stderr, "Error\n");
					exit(0);
				}
			}
		} 
		else{
			fprintf(stderr, "Warning: Unrecognized field %s\n", *argv);
		}
		argc--;
		argv++;
	}
	
	if(strcmp(ret.url, "") == 0){
		fprintf(stderr, "Error: Require a --url to be specified\n");
		exit(0);
	}
	if(strcmp(ret.target, "") == 0){
		fprintf(stderr, "Error: Require a --target to be specified\n");
		exit(0);
	}
	
	return ret;
}

int main(int argc, char *argv[]){
	struct myargs args = parseArgs(argc, argv);	
}
