


#include <iostream>
#include <librdkafka/rdkafka.h>
#include <entraidkafka.h>

using namespace std;


#define SETCONFIG(CONF, KEY, VALUE)     if (rd_kafka_conf_set(CONF, KEY, VALUE, \
    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) { \
    fprintf(stderr, "%s\n", errstr); \
    exit(1); \
    }

static void on_delivery(rd_kafka_t* rk, const rd_kafka_message_t* rkmessage, void* opaque) {
    if (rkmessage->err)
        fprintf(stderr, "Message delivery failed: %s\n",
            rd_kafka_message_errstr(rkmessage));
}

static void log_cb(const rd_kafka_t* rk, int level, const char* fac, const char* buf) {
    fprintf(stderr, "%d [%s] %s\n", level, fac, buf);
}

int main()
{
    char errstr[512];
    rd_kafka_conf_t* conf = rd_kafka_conf_new();

    rd_kafka_conf_set_dr_msg_cb(conf, on_delivery);

    SETCONFIG(conf, "client.id", "mttest");
    SETCONFIG(conf, "bootstrap.servers", "MTKafka0.MTKafkaMulti-Int-MWHE01.MWHE01.ap.gbl:9070");
    //SETCONFIG(conf, "bootstrap.servers", "localhost:9070");
    SETCONFIG(conf, "security.protocol", "SASL_PLAINTEXT");
    SETCONFIG(conf, "sasl.mechanism", "OAUTHBEARER");
    
    //MSI Identity example
    SETCONFIG(conf, "sasl.oauthbearer.config", " tokenScope=api://1c0b8c88-563f-4b97-abdf-207172a50d2c/.default msiClientId=d6966576-1b01-4458-aeb0-31b5deececde");
    //FCI Identity example
    //SETCONFIG(conf, "sasl.oauthbearer.config", " tokenScope=api://1c0b8c88-563f-4b97-abdf-207172a50d2c/.default msiClientId=d6966576-1b01-4458-aeb0-31b5deececde tenantId=975f013f-7f24-47e8-a7d3-abc4752bf346 clientId=e7fce171-7556-4408-a693-f5728189f550");
    //SN+I Certificate example
   // SETCONFIG(conf, "sasl.oauthbearer.config", " tokenScope=api://1c0b8c88-563f-4b97-abdf-207172a50d2c/.default certLocation=LocalMachine/My certSub=*.magnetarcerttest.binginternal.com tenantId=72f988bf-86f1-41af-91ab-2d7cd011db47 clientId=1c3c7e45-4c3d-41dc-9691-74240fe974c5");   
    //workload identity example
    //SETCONFIG(conf, "sasl.oauthbearer.config", "tokenScope=api://1c0b8c88-563f-4b97-abdf-207172a50d2c/.default");

    SETCONFIG(conf, "debug", "all");
    rd_kafka_conf_set_oauthbearer_token_refresh_cb(conf, token_refresh_cb);
    //SETCONFIG(conf, "plugin.library.paths", "entraidkafka.dll");
    rd_kafka_conf_enable_sasl_queue(conf, 1);
    rd_kafka_conf_set_log_cb(conf, log_cb);

    rd_kafka_topic_conf_t* topic_conf = rd_kafka_topic_conf_new();
    SETCONFIG(conf, "acks", "all");
    SETCONFIG(conf, "compression.codec", "gzip");
    rd_kafka_t* rk;
    if (!(rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf,
        errstr, sizeof(errstr)))) {
        fprintf(stderr, "Failed to create new producer: %s\n", errstr);
        exit(1);
    }

    rd_kafka_sasl_background_callbacks_enable(rk);

    rd_kafka_topic_t* rkt = rd_kafka_topic_new(rk, "CITestDotNet", topic_conf);

    char* payload = new char[1];
    payload[0] = 't';
    const char* key = "";
    if (rd_kafka_produce(rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, payload, 1, key, 0,
        NULL) == -1) {
        fprintf(stderr, "Failed to produce: %s\n",
            rd_kafka_err2str(rd_kafka_last_error()));
    }

    auto err = rd_kafka_flush(rk, 60000);
    if (err) {
        fprintf(stderr, "Failed to flush: %s\n", rd_kafka_err2str(err));
    }
}