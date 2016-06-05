<h1><a id="user-content-rfid2wifi" class="anchor" href="#rfid2wifi" aria-hidden="true"><span class="octicon octicon-link"></span></a>RFID to WiFi interface</h1>

<h3> It seems the sketches in this repository don't work as expected and need to be fixed. Use them only as starting point for further development!! </h3>

Combining the ESP8266-7 board and MFRC522 (https://github.com/miguelbalboa/rfid) project to create a RFID to WiFi interface for the rolling stock localisation in model railroad control programs (main target is Rocrail - www.rocrail.net, as this is the program I'm using).

Requirements: 
- ESP8266 Arduino Core (https://github.com/esp8266/Arduino)
- MFRC522 library (https://github.com/miguelbalboa/rfid)

<a name="hardware"></a>
<h2><a id="hardware" class="anchor" href="#hardware" aria-hidden="true"><span class="octicon octicon-link"></span></a>Hardware</h2>

The connections between the ESP8266 and the MFRC522 board are described in the code.

<a name="functional description"></a>
<h2><a id="to-do" class="anchor" href="#func-desc" aria-hidden="true"><span class="octicon octicon-link"></span></a>Small functional description</h2>
As in the rfid2ln project, the RFID data is sent over to the controlling PC in the same (Loconet) format, using a variable length message type (0xEx), with 14 bytes length:

`
0xE4 0x0E 0x41 <ADDR_H> <ADDR_L> <UID0_LSB> <UID1_LSB> <UID2_LSB> <UID3_LSB> <UID4_LSB> <UID5_LSB> <UID6_LSB> <UID_MSBS> <CHK_SUMM>
`

where the UIDX_LSB contains the bite b6..b0 of the corresponding UIDx, and the UID_MSBS contains the MSBits of 
UID0..UID6 as b0..b6. 
The ADDR_H & ADDR_L are the sensor address bytes (range 1..4095).  

Because this interface is desined to work with Rocrail as the LocoIO does, it has a board address (default 88) and a sensor address (addr_h, addr_l, default 0-1). The configuring/programming of the board can be done using the LocoIO programming facility of Rocrail; for the sensor address, the Port1 should be used. To keep the compatibility with Rocrail, the sensor address range is 0..4095 and sensor address codification is matched to the Rocrail one.

<a name="user-content-license"></a>
<h2><a id="user-content-license" class="anchor" href="#license" aria-hidden="true"><span class="octicon octicon-link"></span></a>License</h2>

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this software, either in source code form or as a compiled binary, for any purpose, commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this software dedicate any and all copyright interest in the software to the public domain. We make this dedication for the benefit of the public at large and to the detriment of our heirs and successors. We intend this dedication to be an overt act of relinquishment in perpetuity of all present and future rights to this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to http://unlicense.org/
