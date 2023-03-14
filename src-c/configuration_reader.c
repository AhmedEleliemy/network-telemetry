#include "configuration_reader.h"


int read_configuration_file(const char * configuration_file_path, user_config * conf)
{
    FILE * file_handler;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    file_handler = fopen(configuration_file_path, "r");
    if (file_handler == NULL)
    {
        fprintf(stderr, "Couldn't open the file %s:\n", configuration_file_path);
        return -1;
    }
    while ((read = getline(&line, &len, file_handler)) != -1)
    {
            if(line[0]=='#')  // ignore comments
                continue;
            char *token1 = strtok(line, "=");
            char *token2 = strtok(NULL, "=");
            token2[strlen(token2)-1]='\0'; // trimming
            if(strcmp(token1,"Broker")==0)
            {
                conf->broker = (char *) malloc (sizeof(char) *strlen(token2));
                memcpy(conf->broker, token2, sizeof(char) *strlen(token2));
            }
            else if(strcmp(token1, "Topic")==0)
            {
                conf->topic = (char *) malloc (sizeof(char) *strlen(token2));
                memcpy(conf->topic, token2, sizeof(char) *strlen(token2));
            }
            else if(strcmp(token1, "Device")==0)
            {
                conf->device = (char *) malloc (sizeof(char) *strlen(token2));
                memcpy(conf->device, token2, sizeof(char) *strlen(token2));
            }
            else if(strcmp(token1, "Filter")==0)
            {
                conf->filter_expression = (char *) malloc (sizeof(char) *strlen(token2));
                memcpy(conf->filter_expression, token2, sizeof(char) *strlen(token2));
            }
            else
            {
                printf("%s\n", token2);
                fprintf(stderr, "UnKnown  field %s:\n", line);
                return -1;
            }
        }
        fclose(file_handler);
        if (line)
            free(line);
        if(conf->device ==NULL || conf->topic == NULL || conf->broker==NULL )
        {
            fprintf(stderr, "Some necessary fields are missing\n");
            return -1;
        }
    return 0;
}

void destroy_user_config (user_config * conf)
{
    free(conf->topic);
    free(conf->broker);
    free(conf->device);
    free(conf->filter_expression);
}