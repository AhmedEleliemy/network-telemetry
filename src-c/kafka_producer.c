#include "kafka_producer.h"

int set_conf_property(rd_kafka_conf_t **conf, const char *propertyName, const char **property) {
    char errstr[512];
    if (rd_kafka_conf_set(*conf, propertyName, *property, errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        fprintf(stderr, "%s\n", errstr);
        rd_kafka_conf_destroy(*conf);
        return -1;
        }
        return 0;
}
void kafka_delivery_msg_handler (rd_kafka_t *rk, void *payload, size_t len,int error_code, void *opaque, void *msg_opaque)
{
    if(error_code!=0)
        printf("not send\n");
}

int initialize_producer(const char * kafka_broker, const char * kafka_topic, rd_kafka_t **producer, rd_kafka_conf_t **producer_conf)
{
    char errstr[512];
    producer_conf[0]= rd_kafka_conf_new();
    set_conf_property(producer_conf, "bootstrap.servers", &kafka_broker);
    rd_kafka_conf_set_dr_cb(producer_conf[0], kafka_delivery_msg_handler);
    producer[0] = rd_kafka_new(RD_KAFKA_PRODUCER, *producer_conf, errstr, sizeof(errstr));
    if (producer==NULL) {
        fprintf(stderr,"%% Failed to create producer: %s\n", errstr);
        return -1;
    }
    else{
        printf("Successfully created\n");
        return 0;
    }
}
int forward_message(int message_key, const char * message, rd_kafka_t *producer, const char *topic){
  printf("working on %s\n",message );
  int res= rd_kafka_producev(producer, RD_KAFKA_V_TOPIC(topic),
                               RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                               RD_KAFKA_V_KEY((void*)&message_key, sizeof(int)),
                               RD_KAFKA_V_VALUE((void*)message, strlen(message)),
                               RD_KAFKA_V_END);
    return res;
}
int destroy_producer(rd_kafka_t *producer){
    printf("Flushing final messages..\n");
    rd_kafka_flush(producer, 1000000);
    rd_kafka_destroy(producer);
    return 0;
}