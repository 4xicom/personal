# EntraID Kafka Client example

This is an example for using librdkafka in C++ with Entra ID token. 


This example is based on the helper lib, entraidkafka published by MT team. 

This helper lib supports

## MSI
~~~
   //MSI Identity example
SETCONFIG(conf, "sasl.oauthbearer.config", " tokenScope=api://1c0b8c88-563f-4b97-abdf-207172a50d2c/.default msiClientId=d6966576-1b01-4458-aeb0-31b5deececde");
~~~

## FCI 
~~~
   //FCI Identity example
SETCONFIG(conf, "sasl.oauthbearer.config", " tokenScope=api://1c0b8c88-563f-4b97-abdf-207172a50d2c/.default msiClientId=d6966576-1b01-4458-aeb0-31b5deececde tenantId=975f013f-7f24-47e8-a7d3-abc4752bf346 clientId=e7fce171-7556-4408-a693-f5728189f550");
~~~

## CN+I Certificate
~~~
   //SN+I Certificate example
SETCONFIG(conf, "sasl.oauthbearer.config", " tokenScope=api://1c0b8c88-563f-4b97-abdf-207172a50d2c/.default certLocation=LocalMachine/My certSub=*.magnetarcerttest.binginternal.com tenantId=72f988bf-86f1-41af-91ab-2d7cd011db47 clientId=1c3c7e45-4c3d-41dc-9691-74240fe974c5");   
~~~

## Workload Identity
~~~
   //workload identity example
SETCONFIG(conf, "sasl.oauthbearer.config", " tokenScope=api://1c0b8c88-563f-4b97-abdf-207172a50d2c/.default");
~~~