How to install.

Prerequisites:

For ubuntu you have to install

libavcodec-dev
libavformat-dev
libavutil-dev
libcurl
gcc
apache2
apache2-bin
apache2-dev

Other way can be installation ffmpeg from sources
Install ffmpeg

git clone git://source.ffmpeg.org/ffmpeg.git
cd ffmpeg
./configure --enable-shared --disable-static --enable-pic
make
sudo make install

make visible ffmpeg shared libraries
create file /etc/ld.so.conf.d/libc.conf

fill it with content:
/usr/local/lib

update ldconfig
sudo ldconfig -v

install httpd24-devel package to get apxs tool
Run install.sh in project folder.
sudo sh install.sh

Configurations:

You have to create the configuration file inside www data folder. (I understand this is not safe :))

Here is the sample configuration file:

{ "API_URL": "https://beta.voicebase.com/services",
  "Version" :"1.1",
  "Key" : "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "pw": "xxxxxxxxxx",
  "language" : "en",
  "transcriptType" : "machine-best",
  "public":"false",
  "noVideo" : "true"
}

It contains test account credentials.
It is json with several fields.
DO NOT FORGET TO RESTRICT ACCESS TO THIS FILES! IT STORES PASSWORDS AS TEXT!

This minimal set of fields.

Here is full list of supported fields:
API_URL  - string  - default value NONE - the Voicebase API URL
Version  - string  - default value NONE - Voicebase API version
Key     - string  - default value NONE - Voicebase accout command line API key
pw     - string  - default value NONE - password for specific account key   
public     - string  - default value NONE - make record public access
rtCallBackURL - string - default value NONE - callback url
transcriptType - string - default value "machine" - type of required transcript
description - string - default value NONE - allows to specify description for all streams via this config
language - string - default value NONE - allow to specify language of the stream
sourceURL - string - default value NONE - allow to specify source URL
recordedDate - string - default value NONE - allow to setup record date string
externalID - string  - default value NONE - external ID
ownerID - string - default value NONE - owner ID
autoCreate - string - default value NONE - autoCreate field
humanRush - string - default value NONE - humanRush field
BufferSize - integer - default value 1000000 - measured in bytes input buffer. Required for input stream parsing.
noVideo - string - default value "false" - if true send video to voicebase servers. Currently Voicebase API does not support video. So if you set it "false" you will not see the video in voicebase account



Test command line:

To stream to voicebase you have to use this kind of URL:
https://your.website.com/configuration.file/stream.name

After you finish streaming the result have to appear in account related with "Key" and "pw" fields in configuration file.

Sample:
curl -k -H "Content-type:application/octet-stream" -v -T 4ddec59e2f56fd9380c05e5dd53f1c3d.raw https://tom.rtccloud.net/voicebase/alex.point/segment-test-oops

In your voicebase account you will see file with name segment-test-oops.




