# SNMP-plugin-for-Snort_2.9.17
[SnortSNMP Plugin](https://www.cysol.co.jp/contrib/snortsnmp/index.html)をSnortのバージョン2.9.17でも動かせるように改修したものです。
本Pluginの著作権者はCyber Solutions Inc.であり、私はPluginのソースコードを少し改修しただけです。

## Guide
The SnortSNMP Guide: https://www.cysol.co.jp/contrib/snortsnmp/snortSnmpGuide.html

## Requirements
#### net-snmp
```
apt-get install libsnmp-dev
sudo apt-get install snmpd
sudo apt-get install snmp
```

#### make cmake
```
apt install make cmake libdaq-dev libdnet-dev libdumbnet-dev libhwloc-dev libluajit-5.1 libssl-dev libpcap-dev libpcre3{,-dev}
apt install flex bison
```

#### install OpenSSL
```
wget https://www.openssl.org/source/openssl-1.1.0.tar.gz
./config
make
sudo make install
```

## Activation & Install
- ```cd /usr/local/src```
- ```sudo wget https://www.snort.org/downloads/snort/snort-2.9.17.tar.gz # or Download Snort 2.9.17 from https://www.snort.org/downloads ```
- ```sudo tar -xvzf snort-2.9.17.tar.gz```
- Copy and paste the contents of this repository into the snort-2.9.17 folder (本リポジトリの中身をsnort-2.9.17フォルダーの中にコピーペーストする) 
- ```sudo ./configure && make &&make install```

## Usage & ReadMe
Please check [Snort SNMP ReadMe] (https://www.cysol.co.jp/contrib/snortsnmp/README.SNMP.txt) for usage.

使い方について[SnortSNMP ReadMe](https://www.cysol.co.jp/contrib/snortsnmp/README.SNMP.txt)をご確認ください。
