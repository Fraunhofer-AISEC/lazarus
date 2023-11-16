# Lazarus: Healing Compromised Devices in the Internet of Small Things

- [Lazarus: Healing Compromised Devices in the Internet of Small Things](#lazarus-healing-compromised-devices-in-the-internet-of-small-things)
  - [Introduction](#introduction)
  - [Prerequisites](#prerequisites)
  - [Build](#build)
  - [Hardware Setup](#hardware-setup)
  - [Network Setup](#network-setup)
  - [Provisioning](#provisioning)
  - [Server Start](#server-start)
  - [Certificate Creation](#certificate-creation)

This project is not maintained. It has been published as part of the following AsiaCCS '20
conference paper:

> Huber, M., Hristozov, S., Ott, S., Sarafov, V., & Peinado, M. (2020, October). The Lazarus Effect:
> Healing Compromised Devices in the Internet of Small Things. In Proceedings of the 15th ACM Asia
> Conference on Computer and Communications Security (pp. 6-19).
> https://doi.org/10.1145/3320269.3384723,
> https://arxiv.org/pdf/2005.09714.pdf

Note that this repository presents a **prototype** implementation and is **not** to be
used in production.

## Introduction
This repository contains the code for Lazarus, a system that enables the remote recovery of
compromised IoT devices. With Lazarus, an IoT administrator can remotely control the code running on
IoT devices unconditionally and within a guaranteed time bound. This makes recovery possible even
in case of severe corruption of the devices’ software stack. We impose only minimal hardware
requirements, making Lazarus applicable even for low-end constrained off-the-shelf IoT devices. We
isolate Lazarus’s minimal recovery trusted computing base from untrusted software both in
time and by using a Trusted Execution Environment (TEE). The temporal isolation prevents secrets
from being leaked through side-channels to untrusted software. Inside the TEE, we place minimal
functionality that constrains untrusted software at runtime.

This PoC implements Lazarus on the ARM Cortex-M33-based microcontroller LPC55S69 from NXP.
Accompanying is a simple IoT hub for device provisioning, secure updates and to show the
recovery functionality. The prototype can recover compromised embedded OSs and applications and
prevents attackers from bricking devices, for example, through flash wear out.

The remainder of this readme shows how to install, test and further develop the Lazarus project.

## Prerequisites
The project was built and tested on Ubuntu 20.04. Other distributions might require adjustments

1. Install the GNU Arm Embedded Toolchain
```sh
sudo apt install gcc-arm-none-eabi
```
Or install the newest version from [here](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads),

1. Install pip
```sh
sudo apt install python3-pip
```

3. Install the necessary python libraries:
```sh
pip3 install ecdsa
pip3 install pyOpenSSL
pip3 install cbor2
```

4. Install a serial terminal of your choice
```sh
sudo apt-get install cutecom lrzsz
```

5. Flashing the software on the board, requires the `crt_emu_cm_redlink` flashing utility. This
requires installing the
[MCUXpresso IDE](https://www.nxp.com/design/software/development-software/mcuxpresso-software-and-tools-/mcuxpresso-integrated-development-environment-ide:MCUXpresso-IDE)

## Build

The projects `lz_dicepp`, `lz_core`, `lz_cpatcher`, `lz_udownloader`,
and `lz_demo_app` can be built via:

```sh
make -r -j$(nproc)
```

All projects are also built and flashed directly onto the device via the provisioning-script
(see [Provisioning](#provisioning)).

## Hardware Setup
The PoC requies an LPC55S69-EVK board, an ESP8266 WiFi-Shield and a Bosch BME280 temperature and
humidity sensor.

The demonstrator works with an ESP8266 board and AT-Commands for the TCP connection to the
backend. Of course, the network driver can be replaced with any other hardware. For the
demonstrator, connect an ESP8266 board to the LPC55S69 evaluation board. It should be a board with
a firmware that supports at least 115200k baud rate supports hardware RTS and CTS flow control.

Connect the WiFi-Shield to the Board:

- 3V3 / 5V and GND can be found on Connector P16 on the LPC55S69
- ESP8266 RX must be connected to LPC55S69 D1 on P18
- ESP8266 TX must be connected to LPC55S69 D0 on P18
- ESP8266 GPIO 13: MTCK / HSPI_MOSI / UART0_CTS must be connected to LPC55S69 D7 on P18
- EXP8266 GPIO 15: HSPI_CS /*UART0_RTS must be connected to LPC55S69 D10 on P18

Make sure, that the ESP is configured for Lazarus or change the configuration in the source code
accordingly. The default setup is:

```
AT+UART_DEF=115200,8,1,0,3
```

Connect a micro-USB cable to the Debug Link Port P6. Make sure there is no jumper set at `DFU`
or `J10`. For more information you can visit the LPC55S69-EVK tutorial:
https://www.nxp.com/document/guide/get-started-with-the-lpc55s69-evk:GS-LPC55S69-EVK

## Network Setup
The Lazarus-Device communicates with a demo server via TCP/IP. The network credentials have to be
provided during provisioning. Create a file `wifi_credentials` in the folder
`lz_hub`. The file must have the following contents adjusted to your
network parameters:

```
ssid="your-wifi-network-id"
ip="192.168.1.0"
pwd="mypassword123$"
port="65433"
```
`ip` and `port` must be configured to the server where the Lazarus backend runs.

## Provisioning
After the board is connected, launch your serial-terminal and select the correct port
(e.g. `/dev/ttyACM1`). Then launch the provisioning script `lz_provision_device.sh`:
```sh
./lz_provision_device.sh
```

## Server Start
Run the Lazarus hub:
```sh
python3 ./lz_hub.py ./certificates ./wifi_credentials
```

## Certificate Creation

The repository contains demo certificates in `lz_hub/certificates`. New certificates can be
reated via the following commands.

```sh
mkdir -p lz_hub/certificates
cd lz_hub/certificates
openssl req -x509 -nodes -days 3650 -newkey ec:<(openssl ecparam -name prime256v1) -keyout code_auth_sk.pem -out code_auth_cert.pem
openssl req -x509 -nodes -days 3650 -newkey ec:<(openssl ecparam -name prime256v1) -keyout hub_sk.pem -out hub_cert.pem
```