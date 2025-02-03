#include "freertos/FreeRTOS.h"
#include "freertos/ringbuf.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "opendroneid.h"
#include "persistenHTTPClient.h"

#include <Arduino.h>
#include <vector>
#include <string.h>
#include <ETH.h>
#include <SPIFFS.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>

using namespace std;

#define FW_VERSION  "1.0.0"
#define DEBUG_MODE            //Enables debug mode


// Network variables
#define ETH_CLK_MODE    ETH_CLOCK_GPIO17_OUT
#define ETH_PHY_POWER   12
bool eth_connected = false;
uint8_t net_wifi_mac[6];
IPAddress net_static_IP = IPAddress(192,168,1,10);
IPAddress net_static_GW = IPAddress(192,168,1,1);
IPAddress net_static_SN = IPAddress(255,255,255,0);
IPAddress net_static_DNS1 = IPAddress(8,8,8,8);
IPAddress net_static_DNS2 = IPAddress(8,8,4,4);
String net_hostname = "dronesniff-wifi-hstnme";

#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)
#define WIFI_CHANNEL_MAX               (13)

uint8_t  wifi_channel = 6;

int current_packet_len;
String hex_packet;
String message_check;
String src_mac;
String src_mac_dot;
uint16_t payload_length;
uint16_t ssid_length;
String ssid;
String currentChecker;
static bool new_packet = false;

String jsonStatus;
String detectionJson;

bool scan_wifi = true;
void sendWIFIdetection(String brand, String model, String type, String droneName, int productId, String mac, String ssid,int8_t rssi);

typedef struct {
  String brand;
  String model;
  String type;
  String productId;
  String droneName;
  String checker; //MAC, SSID, BOTH
  String droneSsid;
  String droneMac;
} dbdrone;

// Define the maximum size of the drone database
const int dbSize = 65;
dbdrone dronesDB[dbSize];


typedef struct {
	uint8_t mac[6];
} __attribute__((packed)) MacAddr;

typedef struct {
	int16_t fctl;
	int16_t duration;
	MacAddr addr1;
	MacAddr addr2;
	MacAddr addr3;
	int16_t seqctl;
	MacAddr addr4;
	unsigned char payload[];
} __attribute__((packed)) WifiHdr;

typedef struct {
	int16_t fctl;
	int16_t duration;
	MacAddr da;
	MacAddr sa;
	MacAddr bssid;
	int16_t seqctl;
	unsigned char payload[];
} __attribute__((packed)) WifiMgmtHdr;

typedef struct {
	int64_t timestamp;
	int16_t interval;
	int16_t capability;
	uint8_t elementdata[];
} __attribute__((packed)) WifiBeaconHdr;


/*** SNIFFING METHODS ***/
static void wifi_sniffer_init(void);
static void wifi_sniffer_channel_loop(void * pvParameters);
static void wifi_sniffer_parse_task(void *arg);
static void wifi_sniffer_set_channel(uint8_t channel);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);


/*** GENERAL METHODS AND PARAMETERS ***/
void update_stats();
void set_net_config();
int readPatterns(const char *patterns);
String system_id = "";
String system_version = FW_VERSION;
void net_event_handler(WiFiEvent_t event);

/*** USEFUL TOOLS ***/
int16_t hex2int(const char *hex);
String macToString(uint8_t* mac);


////////////////////////////////////////////////////////////////////////////////
// DRONE DB
////////////////////////////////////////////////////////////////////////////////
const char* drone_patterns =
    //VENDOR,NAME,TYPE,Id,IdName,must_match,ssid,mac
    "XIAOMI,Generic,DRONE,1100,Xiaomi Generic,MAC,amba_boss_,B0C090\n"
    "3DR,Generic,DRONE,1200,3DR Generic,MAC,,8ADC96\n"
    "eHang,Generic,DRONE,1300,eHANG Generic,MAC,eHang_,4C4576\n"
    "JJRC,Generic,DRONE,1400,HERON Generic,MAC,,38E26E\n"
    "PROPEL,Generic,DRONE,1500,PROPEL Generic,BOTH,HD Video Drone,EC3DFD\n"
    "PROPEL,Generic,DRONE,1500,PROPEL Generic,BOTH,HD Video Drone,28F366\n"
    "PROPEL,Generic,DRONE,1500,PROPEL Generic,BOTH,HD Video Drone,E0B94D\n"
    "DJI-WIFI,Generic,DRONE,500,DJI-WIFI Generic,MAC,,60601F\n"
    "DJI-WIFI,Generic,DRONE,500,DJI-WIFI Generic,MAC,,481CB9\n"
    "DJI-WIFI,Generic,DRONE,500,DJI-WIFI Generic,MAC,,34D262\n"
    "PARROT,Generic,DRONE,1000,Parrot Generic,MAC,BebopDrone,A01430\n"
    "PARROT,Generic,DRONE,1000,Parrot Generic,MAC,Bebop2,903AE6\n"
    "PARROT,Generic,DRONE,1000,Parrot Generic,MAC,ardrone2,00267E\n"
    "PARROT,Generic,DRONE,1000,Parrot Generic,MAC,ardrone2,9003B7\n"
    "PARROT,Generic,DRONE,1000,Parrot Generic,MAC,,00121C\n"
    "PARROT,Generic,DRONE,1000,Parrot Generic,MAC,,A0143D\n"
    "HUBSAN,Generic,DRONE,1700,Hubsan Generic,MAC,HUBSAN_,98AAFC7\n"
    "POTENSIC,Generic,DRONE,3000,Potensic Generic,BOTH,Potensic_,0CCF89\n"
    "OBEST,Generic,DRONE,3100,OBEST Generic,BOTH,FLOW_,ACD829\n";

////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// CONFIGURATION
////////////////////////////////////////////////////////////////////////////////
void setup() {
 
  Serial.begin(115200); 
  vTaskDelay(pdMS_TO_TICKS(2000));

  WiFi.macAddress(net_wifi_mac);
  char _sys_id[12];
  sprintf(_sys_id,"DSW%02X%02X%02X%02X%02X%02X",net_wifi_mac[0],net_wifi_mac[1],net_wifi_mac[2],net_wifi_mac[3],net_wifi_mac[4],net_wifi_mac[5]);
  system_id = String(_sys_id);
    
  // Ethernet Interface init
  Serial.println("\n[i] Initializing Network services.");
  set_net_config();

  //read drone patters db
  readPatterns(drone_patterns);

  Serial.println("\n[i] Initializing Packet monitoring service.");
  wifi_sniffer_init();

  /*** SPLASH SCREEN ***/
  Serial.println("");
  Serial.println("################################");
  Serial.println("##### DETECTOR INFORMATION");
  Serial.println("##### "+system_id);
  Serial.println("##### OS: "+String(FW_VERSION));
  Serial.println("################################");
  Serial.println("");

  Serial.println("[i] Starting WIFI UAV drone detection...");
}

////////////////////////////////////////////////////////////////////////////////
// MAIN LOOP
////////////////////////////////////////////////////////////////////////////////

void loop() 
{
  Serial.print("[i] Main loop running on core ");
  Serial.println(xPortGetCoreID());

  while(1){
    //update_stats();
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}


////////////////////////////////////////////////////////////////////////////////
///// FUNCTIONS
////////////////////////////////////////////////////////////////////////////////


//Initializes wifi sniffer task
void wifi_sniffer_init(void){
  //nvs_flash_init();
  //tcpip_adapter_init();
  //ESP_ERROR_CHECK( esp_event_loop_init(wifi_event_handler, NULL) );
  
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  //ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );

  const wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };

  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_channel(wifi_channel, WIFI_SECOND_CHAN_NONE);
  
  xTaskCreatePinnedToCore(wifi_sniffer_channel_loop, "WSChannelsTask", 2000, NULL, 3, NULL, 0); 
  Serial.println(F("[C] Sniffer initialized correctly."));
}

//Channel hopping Task
void wifi_sniffer_channel_loop(void * pvParameters){
  Serial.print(F("[+] Wifi Channel Hopper Task started on core "));
  Serial.println(xPortGetCoreID());

  for(;;){
      wifi_sniffer_set_channel(wifi_channel);
      wifi_channel = (wifi_channel % WIFI_CHANNEL_MAX) + 1;
      Serial.print("Scanning WIFI. CHANNEL: ");
      Serial.println(wifi_channel);
    vTaskDelay(pdMS_TO_TICKS(500));
  }
}

// ESP set channel helper
void wifi_sniffer_set_channel(uint8_t channel) {
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

//Handle new packet from wifi interface
void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {

  if (type != WIFI_PKT_MGMT) return;

  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buff;
  int len=pkt->rx_ctrl.sig_len;

	len-=sizeof(WifiMgmtHdr);
	if (len<0) return;  //Corrupted packet, neither header size.
  uint8_t* packet_frame;

  WifiMgmtHdr *wHeader=(WifiMgmtHdr*)pkt->payload;

  int fctl=ntohs(wHeader->fctl);
  if((fctl == 0x8000)){

    WifiBeaconHdr *bHeader=(WifiBeaconHdr*)wHeader->payload;
    len-=sizeof(WifiBeaconHdr);
    if (len<0) return;

    uint8_t *ep=bHeader->elementdata; 
    int fixed_params_length = 12; //Known initial fixed params length
    for (int i = 0; i < (len - 4); i++) {

      //Get SSID
      if(ep[i]==0x00){
        for (int pox = 0; pox < ep[i+1]; pox++) {
           ssid =  ssid + (char) ep[i+2+pox];
        }
      }
      i += ep[i+1]+1; //move to next TAG 

    }
  }

  //WIFI DECODE TEST ------------------------
  if (scan_wifi)
  {

    bool found = false;
    new_packet = false;
    hex_packet = "";
    current_packet_len = pkt->rx_ctrl.sig_len;

    for (int i = 0; i < current_packet_len; i++) {
      if (pkt->payload[i] < 0x10) {
        hex_packet += '0';
      }
      hex_packet += String(pkt->payload[i], HEX);
    }

    src_mac_dot = String(hex_packet[20]) + String(hex_packet[21]) + ":" + String(hex_packet[22]) + String(hex_packet[23]) + ":" + String(hex_packet[24]) + String(hex_packet[25]) + ":" + String(hex_packet[26]) + String(hex_packet[27]) + ":" + String(hex_packet[28]) + String(hex_packet[29]) + ":" + String(hex_packet[30]) + String(hex_packet[31]);
    src_mac = String(hex_packet[20]) + String(hex_packet[21]) + String(hex_packet[22]) + String(hex_packet[23]) + String(hex_packet[24]) + String(hex_packet[25]) + String(hex_packet[26]) + String(hex_packet[27]) + String(hex_packet[28]) + String(hex_packet[29]) + String(hex_packet[30]) + String(hex_packet[31]);
    src_mac.toUpperCase();

    for (int i = 0; i < dbSize; i++) {
      currentChecker = dronesDB[i].checker;

      if (currentChecker == "BOTH" && ssid.indexOf(dronesDB[i].droneSsid) != -1 && src_mac.indexOf(dronesDB[i].droneMac) != -1) {
        Serial.print("NEW WIFI DETECTION by BOTH SSID:  --> ");
        Serial.print(ssid);
        Serial.print(" DRONE: ");
        Serial.println(dronesDB[i].droneName);
        //sendWIFIdetection(dronesDB[i].brand, dronesDB[i].model, dronesDB[i].type, dronesDB[i].droneName, dronesDB[i].productId.toInt(), src_mac, ssid, pkt->rx_ctrl.rssi);
        break;
      }
      if (currentChecker == "SSID" && ssid.indexOf(dronesDB[i].droneSsid) != -1) {
        Serial.print("NEW WIFI DETECTION by SSID:  --> ");
        Serial.print(ssid);
        Serial.print(" DRONE: ");
        Serial.println(dronesDB[i].droneName);
        //sendWIFIdetection(dronesDB[i].brand, dronesDB[i].model, dronesDB[i].type, dronesDB[i].droneName, dronesDB[i].productId.toInt(), src_mac, ssid, pkt->rx_ctrl.rssi);
        break;
      }
      if (currentChecker == "MAC" && src_mac.indexOf(dronesDB[i].droneMac) != -1) {
        Serial.print("NEW WIFI DETECTION by MAC: --> ");
        Serial.print(src_mac);
        Serial.print(" DRONE: ");
        Serial.println(dronesDB[i] .droneName);
        //sendWIFIdetection(dronesDB[i].brand, dronesDB[i].model, dronesDB[i].type, dronesDB[i].droneName, dronesDB[i].productId.toInt(), src_mac, ssid, pkt->rx_ctrl.rssi);
        break;
      }

    }
  }

  // ----------------------------------------
  ssid = "";
  src_mac = "";
  src_mac_dot = "";
  return;

}

void sendWIFIdetection(String brand, String model, String type, String droneName, int productId, String mac, String ssid,int8_t rssi)
{
  DynamicJsonDocument doc_detection(1024);

  doc_detection["event"] = "detection";
  doc_detection["data"]["mac_addr"] = mac;
  doc_detection["data"]["model_id"] = productId;
  doc_detection["data"]["model_name"] = droneName;
  doc_detection["data"]["serial"] = droneName;
  doc_detection["data"]["type"] = "wifi";

  serializeJson(doc_detection, detectionJson);

  //client->send(detectionJson);
  detectionJson = "";
}

///////////////////////////////////////////////////////////////////////////
//// UTILS
///////////////////////////////////////////////////////////////////////////


void net_event_handler(WiFiEvent_t event) {
  switch (event) {
    case ARDUINO_EVENT_ETH_START:
      Serial.println(F("[-] Ethernet service started"));
      break;
    case ARDUINO_EVENT_ETH_CONNECTED:
      Serial.println(F("[+] Ethernet connected"));
      break;
    case ARDUINO_EVENT_ETH_GOT_IP:
      Serial.print("[*] ETH MAC: ");
      Serial.print(ETH.macAddress());
      Serial.print(", IPv4: ");
      Serial.print(ETH.localIP());
      if (ETH.fullDuplex()) {
        Serial.print(", FULL_DUPLEX");
      }else{
        Serial.print(", HALF_DUPLEX");
      }
      Serial.print(", ");
      Serial.print(ETH.linkSpeed());
      Serial.println("Mbps");
      eth_connected = true;
      vTaskDelay(pdMS_TO_TICKS(200));
      break;
    case ARDUINO_EVENT_ETH_DISCONNECTED:
      Serial.println(F("[-] Ethernet disconnected."));
      eth_connected = false;
      break;
    case ARDUINO_EVENT_ETH_STOP:
      Serial.println(F("[!] Ethernet service stopped."));
      eth_connected = false;
      break;
    default:
      break;
  }
}

// HEX to DEC conversion
int16_t hex2int(const char *hex) {
  uint16_t value;  // unsigned to avoid signed overflow
  for (value = 0; *hex; hex++) {
    value <<= 4;
    if (*hex >= '0' && *hex <= '9')
      value |= *hex - '0';
    else if (*hex >= 'A' && *hex <= 'F')
      value |= *hex - 'A' + 10;
    else if (*hex >= 'a' && *hex <= 'f')
      value |= *hex - 'a' + 10;
    else
      break;  // stop at first non-hex digit
  }
  return value;
}

//Returns string formatted mac address
String macToString(uint8_t* mac){
    char _string[20];
    sprintf(_string,"%02X:%02X:%02X:%02X:%02X:%02X",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
  return String(_string);
}

////////////////////////////////////////////////////////////////////////////////
// GETTERS & SETTERS
////////////////////////////////////////////////////////////////////////////////

//Apply current network settings
void set_net_config(){
  WiFi.onEvent(net_event_handler);
  //Ethernet
  ETH.begin(0, ETH_PHY_POWER, ETH_PHY_MDC, ETH_PHY_MDIO, ETH_PHY_TYPE, ETH_CLK_MODE);
  Serial.println("[C] Configuring Ethernet with static IP: "+net_static_IP.toString());
  ETH.config(net_static_IP, net_static_GW, net_static_SN, net_static_DNS1,net_static_DNS2);
  //Wait 5 secs to connect
  long start_time = millis();
  while(!eth_connected && (millis()-start_time < 5000)){
    vTaskDelay(pdMS_TO_TICKS(250));
  }
}

int readPatterns(const char *patterns){

  String readed_data = "";
  readed_data = String(patterns);
  
  String newDrone = "";
  int readed_len = readed_data.length();
  int count = 0;
  int onecommaIndex;
  int twoCommaIndex;
  int threeCommaIndex;
  int fourCommaIndex;
  int fiveCommaIndex;
  int sixCommaIndex;
  int sevenCommaIndex;
  int eigthCommaIndex;
  String droneBrand;
  String droneModel;
  String droneType;
  String droneProductId;
  String droneName;
  String droneChecker;
  String droneSsid;
  String droneMac;

  for (int i = 0; i < readed_len; i++) {
    if (readed_data[i] == '\n') {

      onecommaIndex = newDrone.indexOf(',');
      twoCommaIndex = newDrone.indexOf(',', onecommaIndex + 1);
      threeCommaIndex = newDrone.indexOf(',', twoCommaIndex + 1);
      fourCommaIndex = newDrone.indexOf(',', threeCommaIndex + 1);
      fiveCommaIndex = newDrone.indexOf(',', fourCommaIndex + 1);
      sixCommaIndex = newDrone.indexOf(',', fiveCommaIndex + 1);
      sevenCommaIndex = newDrone.indexOf(',', sixCommaIndex + 1);
      eigthCommaIndex = newDrone.indexOf(',', sevenCommaIndex + 1);

      //VENDOR,NAME,TYPE,Id,IdName,must_match,ssid,mac

      droneBrand = newDrone.substring(0, onecommaIndex);
      droneModel = newDrone.substring(onecommaIndex + 1, twoCommaIndex);
      droneType = newDrone.substring(twoCommaIndex + 1, threeCommaIndex);
      droneProductId = newDrone.substring(threeCommaIndex + 1, fourCommaIndex);
      droneName = newDrone.substring(fourCommaIndex + 1, fiveCommaIndex);
      droneChecker = newDrone.substring(fiveCommaIndex + 1, sixCommaIndex);
      droneSsid = newDrone.substring(sixCommaIndex + 1, sevenCommaIndex);
      droneMac = newDrone.substring(sevenCommaIndex + 1, eigthCommaIndex);

      dbdrone A = {droneBrand, droneModel, droneType, droneProductId, droneName, droneChecker, droneSsid, droneMac};
      dronesDB[count] = A;

      Serial.print("[+] New Drone pattern added. SSID: ");
      Serial.println(A.droneSsid);

      count++;
      newDrone = "";

    } else {
      newDrone = newDrone + readed_data[i];
    }
  }
  return count;
}
