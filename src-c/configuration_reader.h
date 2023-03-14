#ifndef SRC_CONFIGURATION_READER
#define SRC_CONFIGURATION_READER

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct user_config{
   char * topic;
   char * broker;
   char * device;
   char * filter_expression;
   char * json_format;

}user_config;

int read_configuration_file(const char * configuration_file_path, user_config * conf);
void destroy_user_config (user_config * conf);

#endif