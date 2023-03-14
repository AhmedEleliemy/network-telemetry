#ifndef SRC_KAFKA_RD_KAFKA_PRODUCER
#define SRC_KAFKA_RD_KAFKA_PRODUCER

#include <librdkafka/rdkafka.h>
#include <string.h>

int set_conf_property(rd_kafka_conf_t **conf, const char *propertyName, const char **property);
int initialize_producer(const char * kafka_brokers, const char * kafka_topic, rd_kafka_t **producer, rd_kafka_conf_t **producer_conf);
int forward_message(int message_key, const char * message, rd_kafka_t *producer, const char *topic);
int destroy_producer(rd_kafka_t *producer);

#endif