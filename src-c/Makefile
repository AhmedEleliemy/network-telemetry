program:
	gcc main.c sniffer.c kafka_producer.c configuration_reader.c -lrdkafka -lpcap  -o myChatter.exe
debug:
	gcc -g main.c sniffer.c kafka_producer.c configuration_reader.c -lrdkafka -lpcap -o myChatter.exe
withfilter:
	gcc main.c sniffer.c kafka_producer.c configuration_reader.c -DFILTER -lrdkafka -lpcap -o myChatter.exe
clean:
	rm *.exe
