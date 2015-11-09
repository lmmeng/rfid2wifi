/**
 * ----------------------------------------------------------------------------
 * This is a MFRC522 library example; see https://github.com/miguelbalboa/rfid
 * for further details and other examples.
 * 
 * NOTE: The library file MFRC522.h has a lot of useful info. Please read it.
 * 
 * Released into the public domain.
 * ----------------------------------------------------------------------------
 * This sample shows how to read and write data blocks on a MIFARE Classic PICC
 * (= card/tag).
 * 
 * BEWARE: Data will be written to the PICC, in sector #1 (blocks #4 to #7).
 * 
 * 
 * Typical pin layout used:
 * -----------------------------------------------------------------------------------------
 *             MFRC522      ESP866
 *             Reader/PCD   
 * Signal      Pin          Pin          
 * -----------------------------------------------------------------------------------------
 * RST/Reset   RST          GPIO4
 * SPI SS      SDA(SS)      GPIO5
 * SPI MOSI    MOSI         GPIO13
 * SPI MISO    MISO         GPIO12
 * SPI SCK     SCK          GPIO14
 * 
 */

#include <SPI.h>
#include <MFRC522.h>
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <EEPROM.h>
#include "secrets_lm.h"
#include "FS.h"

const char* ssid = SSID_RR;  //update the secrets.h file
const char* password = PASS_RR; //update the secrets.h file

IPAddress ipBroad(224,0,0,1); 
const int port = 1235;
const char STARS[] PROGMEM = "***************************************************************************";

// Create an instance of the server
// specify the port to listen on as an argument
//WiFiServer server(port);
WiFiUDP g_udp;


#if defined(ARDUINO_ESP8266_ESP01)
  #define RST_PIN         4           // Configurable, see typical pin layout above
  #define SS_PIN          5           // Configurable, see typical pin layout above
#endif

    // --------------------------------------------------------
    // OPC_PEER_XFER CMD's
    // --------------------------------------------------------

#define CMD_WRITE            0x01    /* Write 1 byte of data from D1*/
#define CMD_READ             0x02    /* Initiate read 1 byte of data into D1*/
#define CMD_MASKED_WRITE     0x03    /* Write 1 byte of masked data from D1. D2 contains the mask to be used.*/
#define CMD_WRITE4           0x05    /* Write 4 bytes of data from D1..D4*/
#define CMD_READ4            0x06    /* Initiate read 4 bytes of data into D1..D4*/
#define CMD_DISCOVER         0x07    /* Causes all devices to identify themselves by their MANUFACTURER_ID, DEVELOPER_ID, PRODUCT_ID and Serial Number*/
#define CMD_IDENTIFY         0x08    /* Causes an individual device to identify itself by its MANUFACTURER_ID, DEVELOPER_ID, PRODUCT_ID and Serial Number*/
#define CMD_CHANGE_ADDR      0x09    /* Changes the device address to the values specified in <DST_L> + <DST_H> in the device that matches */
                                        /* the values specified in <ADRL> + <ADRH> + <D1>..<D4> that we in the reply to the Discover or Identify command issued previously*/
#define CMD_RECONFIGURE      0x4F    /* Initiates a device reconfiguration or reset so that any new device configuration becomes active*/

    // Replies
#define CMDR_WRITE           0x41    /* Transfers a write response in D1*/
#define CMDR_READ            0x42    /* Transfers a read response in D1*/
#define CMDR_MASKED_WRITE    0x43    /* Transfers a masked write response in D1*/
#define CMDR_WRITE4          0x45    /* Transfers a write response in D1..D4*/
#define CMDR_READ4           0x46    /* Transfers a read response in D1..D4*/
#define CMDR_DISCOVER        0x47    /* Transfers an Discover response containing the MANUFACTURER_ID, DEVELOPER_ID, PRODUCT_ID and Serial Number*/
#define CMDR_IDENTIFY        0x48    /* Transfers an Identify response containing the MANUFACTURER_ID, DEVELOPER_ID, PRODUCT_ID and Serial Number*/
#define CMDR_CHANGE_ADDR     0x49    /* Transfers a Change Address response.*/
#define CMDR_RECONFIGURE     0x4F    /* Acknowledgement immediately prior to a device reconfiguration or reset*/

//Other LN definitions
#define SEN_QUERY_LOW_ADDRESS   0x79    /* 1017 & 0x007F - 7 bits low address for the sensors query address 1017*/
#define SEN_QUERY_HIGH_ADDRESS  0x07    /* (1017 >> 8) & 0x07 - high address bits for the sensors query address 1017*/
#define LN_MESS_LEN_PEER 16

#define ADDR_NODE_ID_H          1
#define ADDR_NODE_ID_L          2
#define ADDR_USER_BASE          3


//Version
#define VER_LOW         0x01
#define VER_HIGH        0X00

#define BOARD_ADDR_LO   89
#define BOARD_ADDR_HI   1

#define NR_OF_PORTS     1
#define NR_OF_SVS       NR_OF_PORTS * 3 + 3
#define UID_LEN         7
#define NR_OF_EXT_SVS   100 + NR_OF_PORTS * 3

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.

MFRC522::MIFARE_Key key;

uint8_t ucBoardAddrHi = BOARD_ADDR_HI;  //board address high; always 1
uint8_t ucBoardAddrLo = BOARD_ADDR_LO;  //board address low; default 89

uint8_t ucAddrHiSen = 0;    //sensor address high
uint8_t ucAddrLoSen = 1;    //sensor address low
uint8_t ucSenType = 0x0F; //input
uint16_t uiAddrSenFull;

bool compareUid(byte *buffer1, byte *buffer2, byte bufferSize);
void copyUid(byte *buffIn, byte *buffOut, byte bufferSize);
void setMessageHeader(uint8_t *SendPacketSensor);
uint8_t processXferMess(uint8_t *LnRecMsg, uint8_t *LnSendMsg);
uint8_t lnCalcCheckSumm(uint8_t *cMessage, uint8_t cMesLen);
uint8_t uiLnSendCheckSumIdx = 13; //last byte is CHK_SUMM
uint8_t uiLnSendLength = 14; //14 bytes
uint8_t uiLnSendMsbIdx = 12;
uint8_t uiStartChkSen;

uint8_t oldUid[UID_LEN] = {0};

uint8_t SendPacketSensor[16];

boolean bSerialOk=false;

#define _SERIAL_DEBUG  0

WiFiServer server(80);

File fIndexHtml;
File fIp;

IPAddress myIp;

/**
 * Initialize.
 */
void setup() {
  
    uint32_t uiStartTimer;
    uint16_t uiElapsedDelay;
    uint16_t uiSerialOKDelay = 5000;
    
    Serial.begin(115200); // Initialize serial communications with the PC
    uiStartTimer = millis();
    do{  //wait for the serial interface, but maximal 1 second.
        uiElapsedDelay = millis() - uiStartTimer;
    } while ((!Serial) && (uiElapsedDelay < uiSerialOKDelay));    // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)

    if(Serial) { //serial interface ok
       bSerialOk = true;
       //Show some details of the loconet setup
       Serial.println();
       Serial.println();
       Serial.println(FPSTR(STARS));
       Serial.println(F("RFID to WIFI Board"));
    }

    EEPROM.begin(256);
        
    ucBoardAddrHi = EEPROM.read(ADDR_NODE_ID_H); //board address high
    ucBoardAddrLo = EEPROM.read(ADDR_NODE_ID_L); //board address low

    if((ucBoardAddrHi == 0xFF) && (ucBoardAddrLo == 0xFF)){ //eeprom empty, first run 
       ucBoardAddrHi = BOARD_ADDR_HI;
       ucBoardAddrLo = BOARD_ADDR_LO;

       EEPROM.write(ADDR_NODE_ID_H, ucBoardAddrHi );
       EEPROM.write(ADDR_NODE_ID_L, ucBoardAddrLo);
  
       ucSenType=0x0F;
       EEPROM.write(ADDR_USER_BASE+2, 0);
       EEPROM.write(ADDR_USER_BASE+1, 0);
       EEPROM.write(ADDR_USER_BASE, ucSenType);

       EEPROM.commit();
    } //if((ucBoardAddrHi == 0xFF) 

    // Rocrail compatible addressing
    uiAddrSenFull = 256 * (EEPROM.read(ADDR_USER_BASE+2) & 0x0F) + 2 * EEPROM.read(ADDR_USER_BASE+1) +
                    ((EEPROM.read(ADDR_USER_BASE+2) & 0x20) >> 5) + 1;

    calcAddrBytes(uiAddrSenFull, &ucAddrLoSen, &ucAddrHiSen);

    ucSenType = EEPROM.read(ADDR_USER_BASE); //"sensor" type = in

    SPI.begin();        // Init SPI bus
    mfrc522.PCD_Init(); // Init MFRC522 card

    // Prepare the key (used both as key A and as key B)
    // using FFFFFFFFFFFFh which is the default at chip delivery from the factory
    for (byte i = 0; i < 6; i++) {
        key.keyByte[i] = 0xFF;
    }

  
    WiFi.begin(ssid, password);
  
    if(bSerialOk){
       Serial.println("");
    }
    
    while (WiFi.status() != WL_CONNECTED) {
      delay(500);
      if(bSerialOk){
         Serial.print(".");
      }
   }//while
   
   if(bSerialOk){
      Serial.println("");
      Serial.println("WiFi connected");
   }

   // Print the IP address
   if(bSerialOk){
      Serial.println(WiFi.localIP());
   }

   // Start the server
   server.begin();
   if(bSerialOk){
      Serial.println("Server started");
   }

    // start UDP server
    g_udp.begin(port);

    setMessageHeader(SendPacketSensor);
    uiStartChkSen = SendPacketSensor[uiLnSendCheckSumIdx];

    if(bSerialOk){
        // Show some details of the loconet setup
        Serial.print(F("Board address: "));
        Serial.print(ucBoardAddrHi);
        Serial.print(F(" - "));
        Serial.println(ucBoardAddrLo);
        Serial.print(F("Full sensor addr: "));
        Serial.println(uiAddrSenFull);
        Serial.print(F("Sensor AddrH: "));
        Serial.print(ucAddrHiSen);
        Serial.print(F(" Sensor AddrL: "));
        Serial.print(ucAddrLoSen);
        Serial.println();
        Serial.println(FPSTR(STARS));
        Serial.println();
    }

    SPIFFS.begin();

    myIp = WiFi.localIP();
} //setup

//#############################################################

/**
 * Main loop.
 */
void loop() {
  unsigned long uiStartTime;
  unsigned long uiActTime;
  bool delaying;
  unsigned char i=0;
  unsigned char j=0;  
  uint16_t uiDelayTime = 1000;

    // Look for new cards
  if ( mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()){
     if(!delaying){   //Avoid to many/to fast reads of the same tag
      
        if(bSerialOk){
           // Show some details of the PICC (that is: the tag/card)
           Serial.print(F("Card UID:"));
           dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
           Serial.println();
        }

        uiStartTime = millis();
        delaying = true;

        SendPacketSensor[uiLnSendCheckSumIdx]= uiStartChkSen; //start with header check summ
        SendPacketSensor[uiLnSendMsbIdx]=0; //clear the byte for the ms bits
        for(i=0, j=5; i< UID_LEN; i++, j++){
           if(mfrc522.uid.size > i){
              SendPacketSensor[j] = mfrc522.uid.uidByte[i] & 0x7F; //loconet bytes haver only 7 bits;
                                                               // MSbit is transmited in the SendPacket[10]
              if(mfrc522.uid.uidByte[i] & 0x80){
                 SendPacketSensor[uiLnSendMsbIdx] |= 1 << i;
              }
              SendPacketSensor[uiLnSendCheckSumIdx] ^= SendPacketSensor[j]; //calculate the checksumm
           } else {
              SendPacketSensor[j] = 0;
           }        
        } //for(i=0

        SendPacketSensor[uiLnSendCheckSumIdx] ^= SendPacketSensor[uiLnSendMsbIdx]; //calculate the checksumm

#if _SER_DEBUG
    if(bSerialOk){
        // Show some details of the PICC (that is: the tag/card)
        Serial.print(F("LN send mess:"));
        dump_byte_array(SendPacketSensor, uiLnSendLength);
        Serial.println();
    } // if(bSerialOk){
#endif

        g_udp.beginPacket(ipBroad, port);
        g_udp.write(SendPacketSensor, uiLnSendLength);
        g_udp.endPacket();

        copyUid(mfrc522.uid.uidByte, oldUid, mfrc522.uid.size);
        
     } else { //if(!delaying)
         uiActTime = millis();  
         if(compareUid( mfrc522.uid.uidByte, oldUid, mfrc522.uid.size)){//same UID  
            if((uiActTime - uiStartTime) > uiDelayTime){
               delaying = false;
            } //if((uiActTime
         } else { //new UID
            delaying = false;
         }
     } //else 
     
    // Halt PICC
    mfrc522.PICC_HaltA();
    // Stop encryption on PCD
    mfrc522.PCD_StopCrypto1();
  } //if ( mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()){    

  // Check if a rocrail client has connected
  uint8_t recLen = g_udp.parsePacket();
  uint8_t recMessage[16]; 
  
  if(recLen){
     g_udp.read(recMessage, recLen);
     g_udp.flush();
     if( ((recMessage[2] != ucBoardAddrLo) || (recMessage[4] != ucBoardAddrHi))) { //new message sent by other
        uint8_t msgLen = recMessage[1];
        uint8_t sendMessage[16]; 
     
#if _SERIAL_DEBUG
    if(bSerialOk){
        Serial.print(F("LN rec mess:"));
        dump_byte_array(recMessage, recLen);
        Serial.println();
        Serial.println(recLen);
    } //if(bSerial
#endif        
        //Change the board & sensor addresses. Changing the board address is working
        if(msgLen == 0x10){  //XFERmessage, check if it is for me. Used to change the address
           //svStatus = sv.processMessage(LnPacket);
         
           processXferMess(recMessage, sendMessage);
           g_udp.beginPacket(ipBroad, port);
           g_udp.write(sendMessage, msgLen);
           g_udp.endPacket();
            
           // Rocrail compatible addressing
           uiAddrSenFull = 256 * (EEPROM.read(ADDR_USER_BASE+2) & 0x0F) + 2 * EEPROM.read(ADDR_USER_BASE + 1) +
                           ((EEPROM.read(ADDR_USER_BASE+2) & 0x20) >> 5) + 1;
                           
           calcAddrBytes(uiAddrSenFull, &ucAddrLoSen, &ucAddrHiSen);
           
           setMessageHeader(SendPacketSensor); //if the sensor address was changed, update the header                
#if _SERIAL_DEBUG
    if(bSerialOk){
        // Show some details of the loconet setup
        Serial.print(F("Changed address. Full sen addr: "));
        Serial.print(uiAddrSenFull);
        Serial.print(F(" Sensor AddrH: "));
        Serial.print(ucAddrHiSen);
        Serial.print(F(" Sensor AddrL: "));
        Serial.print(ucAddrLoSen);
        Serial.println();
    } //if(bSerial
#endif
        } //if(msgLen == 0x10)
      }//if( ((recMessage[2]
   } //if(recLen)

   // Check if a web-client has connected
   WiFiClient webClient = server.available();

   //if the client has some data
   if(webClient.available()){
      // Read the first line of the request
      String req = webClient.readStringUntil('\r');
      if(bSerialOk){
         Serial.println(req);
      }
      webClient.flush();

      int ipRecIdx = req.indexOf("1=");
      if(ipRecIdx != -1){
          String ipRead = req.substring(ipRecIdx+2);
          myIp[0] = ipRead.toInt();
      }

      ipRecIdx = req.indexOf("2=");
      if(ipRecIdx != -1){
          String ipRead = req.substring(ipRecIdx+2);
          myIp[1] = ipRead.toInt();
      }

      ipRecIdx = req.indexOf("3=");
      if(ipRecIdx != -1){
          String ipRead = req.substring(ipRecIdx+2);
          myIp[2] = ipRead.toInt();
      }

      ipRecIdx = req.indexOf("4=");
      if(ipRecIdx != -1){
          String ipRead = req.substring(ipRecIdx+2);
          myIp[3] = ipRead.toInt();
      }

      ipRecIdx = req.indexOf("BA=");
      if(ipRecIdx != -1){
          String ipRead = req.substring(ipRecIdx+3);
          ucBoardAddrLo = ipRead.toInt();
          EEPROM.write(ADDR_NODE_ID_L, ucBoardAddrLo);
          EEPROM.commit();
      }

      ipRecIdx = req.indexOf("SA=");
      if(ipRecIdx != -1){
          String ipRead = req.substring(ipRecIdx+3);
          uiAddrSenFull = ipRead.toInt();

          calcAddrBytes(uiAddrSenFull, &ucAddrLoSen, &ucAddrHiSen);
          setMessageHeader(SendPacketSensor); //if the sensor address was changed, update the header                

#if _SERIAL_DEBUG
    if(bSerialOk){
          Serial.print("Full: ");
          Serial.println(uiAddrSenFull);

          Serial.print("low ");
          Serial.println(ucAddrLoSen);

          Serial.print("high ");
          Serial.println(ucAddrHiSen);
    }
#endif
          EEPROM.write(ADDR_USER_BASE+2, ucAddrHiSen);
          EEPROM.write(ADDR_USER_BASE+1, ucAddrLoSen);
 
          EEPROM.commit();
      }

      fIndexHtml = SPIFFS.open("/index.html", "r");
      if (!fIndexHtml) {
         if(bSerialOk){
            Serial.println("file open failed");
         }
      }

      //read the full file
      String s=fIndexHtml.readStringUntil(EOF);
      fIndexHtml.close();
      
      int ipIdx = s.indexOf("function");

      String htmlBegin = s.substring(0, ipIdx);
      String htmlEnd = s.substring(ipIdx);
      String sBoardAddrLo = String(ucBoardAddrLo);
      String sBoardAddrHi = String(ucBoardAddrHi);

      String htmlFull = "";
      
      htmlFull = htmlBegin + "var boardIp1 = ";
      htmlFull +=  String(myIp[0]);
      htmlFull += "; \n";
      htmlFull += "var boardIp2 = ";
      htmlFull +=  String(myIp[1]);
      htmlFull += "; \n";
      htmlFull += "var boardIp3 = ";
      htmlFull +=  String(myIp[2]);
      htmlFull += "; \n";
      htmlFull += "var boardIp4 = ";
      htmlFull +=  String(myIp[3]);
      htmlFull += "; \n ";
      htmlFull += "var boardAddr = ";
      htmlFull +=  String(sBoardAddrLo);
      htmlFull += "; \n ";
      htmlFull += "var senAddr = ";
      htmlFull +=  String(uiAddrSenFull);
      htmlFull += "; \n\n ";
      htmlFull += htmlEnd;

#if 0
      if(bSerialOk){
         Serial.println(htmlFull);
      }
#endif
      // Send the response to the client
      webClient.print(htmlFull);

      if(bSerialOk){
         Serial.println("Client disonnected");
      }
   }
}

/**
 * Helper routine to dump a byte array as hex values to Serial.
 */
void dump_byte_array(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
       if(bSerialOk){     
          Serial.print(buffer[i] < 0x10 ? " 0" : " ");
          Serial.print(buffer[i], HEX);
       } //if(bSerial
    }
}

uint8_t processXferMess(uint8_t LnRecMsg[16], uint8_t cOutBuf[16]){
    
    unsigned char ucPeerRCommand = 0;
    unsigned char ucPeerRSvIndex = 0;
    unsigned char ucPeerRSvValue = 0;
    unsigned char ucTempData = 0;
    
    if ((LnRecMsg[3] != ucBoardAddrLo) && (LnRecMsg[3] != 0)) { //no my low address and no broadcast
        return (0);
    } else if ((LnRecMsg[4] != ucBoardAddrHi) && (LnRecMsg[4] != 0x7F)) {//not my low address and not address programming
        return (0);
    } else {//message for me
        cOutBuf[0x00] = 0xE5; //allways PEER
        cOutBuf[0x01] = 0x10; //always 16 bytes long
        cOutBuf[0x0A] = 0; //clear the cOutBuf[0x0A];

        if (LnRecMsg[0x05] & 0x08) //MSbit in reg5->3
            LnRecMsg[0x09] |= 0x80;
        if (LnRecMsg[0x05] & 0x04) //MSbit in reg5->2
            LnRecMsg[0x08] |= 0x80;
        if (LnRecMsg[0x05] & 0x02) //MSbit in reg5->1
            LnRecMsg[0x07] |= 0x80;
        if (LnRecMsg[0x05] & 0x01) //MSbit in reg5->0
            LnRecMsg[0x06] |= 0x80;

        if (LnRecMsg[0x0A] & 0x08) //MSbit in regA->3
            LnRecMsg[0x0E] |= 0x80;
        if (LnRecMsg[0x0A] & 0x04) //MSbit in regA->2
            LnRecMsg[0x0D] |= 0x80;
        if (LnRecMsg[0x0A] & 0x02) //MSbit in regA->1
            LnRecMsg[0x0C] |= 0x80;
        if (LnRecMsg[0x0A] & 0x01) //MSbit in regA->0
            LnRecMsg[0x0B] |= 0x80;

        ucPeerRCommand = LnRecMsg[0x06];
        ucPeerRSvIndex = LnRecMsg[0x07];
        ucPeerRSvValue = LnRecMsg[0x09];

        if (ucPeerRCommand == CMD_WRITE) { //write command. Save the new data and answer to sender
            if (ucPeerRSvIndex == 0) { //board address high
                ucPeerRSvValue &= 0xFE; //LocoHDL is increasing this value with each write cycle
                cOutBuf[0x0B] = ucBoardAddrHi;
                cOutBuf[0x0E] = 0;
            } else if (ucPeerRSvIndex == 1) { //new low_address
                ucBoardAddrLo = ucPeerRSvValue;
                // initMessagesArray();
                cOutBuf[0x0B] = 0x7F;
                ucBoardAddrLo = ucPeerRSvValue;
                cOutBuf[0x0E] = ucPeerRSvValue;
                EEPROM.write(ADDR_NODE_ID_L, ucPeerRSvValue); //save the new value
                EEPROM.commit();
            } else if (ucPeerRSvIndex == 2) { //new high_address
                if (ucPeerRSvValue != 0x7F) {
                    //initMessagesArray();
                    ucBoardAddrHi = ucPeerRSvValue;
                    EEPROM.write(ADDR_NODE_ID_H, ucPeerRSvValue); //save the new value
                    EEPROM.commit();
                }
                cOutBuf[0x0B] = 0x7F;
                cOutBuf[0x0E] = 0x7F;
            } else if ((ucPeerRSvIndex < NR_OF_SVS) /*|| 
                       ((ucPeerRSvIndex > 100) && (ucPeerRSvIndex < NR_OF_EXT_SVS))*/) { //nr_of_ports (1) * 3 register starting with the address 3
                if ((ucPeerRSvIndex % 3) != 0) { // do not change the type (leave it as IN)
                    EEPROM.write(ucPeerRSvIndex, ucPeerRSvValue); //save the new value
                    EEPROM.commit();
                }
                cOutBuf[0x0B] = ucBoardAddrHi; 
                ucTempData = EEPROM.read(ucPeerRSvIndex);
                if (ucTempData & 0x80) { //msb==1 => sent in PXCTL2
                   cOutBuf[0x0A] |= 0x08; //PXCTL2.3 = D8.7
                }
                cOutBuf[0x0E] = ucTempData & 0x7F;
            } //if (ucPeerRSvIndex < (NR_OF_PORTS * 3 + 3))
            cOutBuf[0x0C] = 0;
            cOutBuf[0x0D] = 0;
        } //if (cLnBuffer[0x06] == CMD_WRITE)
        if ((ucPeerRCommand == CMD_READ) || (ucPeerRCommand == 0)) { //read command. Answer to sender
            cOutBuf[0x0B] = 0x01;

            ucTempData = EEPROM.read(ucPeerRSvIndex);
            if (ucTempData & 0x80) { //msb==1 => sent in PXCTL2
                cOutBuf[0x0A] |= 0x02; //PXCTL2.1 = D6.7
            }
            cOutBuf[0x0C] = ucTempData & 0x7F;

            ucTempData = EEPROM.read(ucPeerRSvIndex + 1);
            if (ucTempData & 0x80) { //msb==1 => sent in PXCTL2
                cOutBuf[0x0A] |= 0x04; //PXCTL2.2 = D7.7
            }
            cOutBuf[0x0D] = ucTempData & 0x7F;

            ucTempData = EEPROM.read(ucPeerRSvIndex + 2);
            if (ucTempData & 0x80) { //msb==1 => sent in PXCTL2
                cOutBuf[0x0A] |= 0x08; //PXCTL2.3 = D8.7
            }
            cOutBuf[0x0E] = ucTempData & 0x7F;
        } //if (cLnBuffer[0x06] == CMD_READ)

        cOutBuf[0x02] = ucBoardAddrLo; // src low address;
        cOutBuf[0x03] = LnRecMsg[0x02]; //dest low addres == received src low address;
        cOutBuf[0x04] = ucBoardAddrHi;
        cOutBuf[0x05] = VER_HIGH; //unsigned char pxct1; (bit 3 = MSBit(b7) version)
        cOutBuf[0x06] = ucPeerRCommand; //0x02;  //unsigned char cmd;
        cOutBuf[0x07] = ucPeerRSvIndex;
        cOutBuf[0x08] = VER_LOW; //LSBits version
        cOutBuf[0x09] = 0x7B;

        cOutBuf[0x0F] = lnCalcCheckSumm(cOutBuf, LN_MESS_LEN_PEER);
    }

    return 1;  //should put the right here
}

/**********char lnCalcCheckSumm(...)**********************
 *
 *
 ******************************/
uint8_t lnCalcCheckSumm(uint8_t *cMessage, uint8_t cMesLen) {
    unsigned char ucIdx = 0;
    char cLnCheckSum = 0;

    for (ucIdx = 0; ucIdx < cMesLen - 1; ucIdx++) //check summ is the last byte of the message
    {
        cLnCheckSum ^= cMessage[ucIdx];
    }

    return (~cLnCheckSum);
}

void setMessageHeader(uint8_t *SendPacketSensor){
    unsigned char k = 0;
    SendPacketSensor[0] = 0xE4; //OPC - variable length message 
    SendPacketSensor[1] = uiLnSendLength; //14 bytes length
    SendPacketSensor[2] = 0x41; //report type 
    SendPacketSensor[3] = (uiAddrSenFull >> 7) & 0x7F; //ucAddrHiSen; //sensor address high
    SendPacketSensor[4] = uiAddrSenFull & 0x7F;; //ucAddrLoSen; //sensor address low 
   
    SendPacketSensor[uiLnSendCheckSumIdx]=0xFF;
    for(k=0; k<5;k++){
      SendPacketSensor[uiLnSendCheckSumIdx] ^= SendPacketSensor[k];
    }
}

void copyUid (byte *buffIn, byte *buffOut, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
        buffOut[i] = buffIn[i];
    }
    if(bufferSize < UID_LEN){
       for (byte i = bufferSize; i < UID_LEN; i++) {
           buffOut[i] = 0;
       }    
    }
}

void calcAddrBytes(uint16_t uiFull, uint8_t *uiLo, uint8_t *uiHi){
    *uiHi = (((uiFull - 1)  >> 8) & 0x0F) + (((uiFull-1) & 1) << 5);
    *uiLo = ((uiFull - 1) & 0xFE) / 2;  
}


