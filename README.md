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

After all packages were istalled run:
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

To stream to voicebase you have to use this kind of URL:
https://your.website.com/configuration.file/stream.name

After you finish streaming the result have to appear in account related with "Key" and "pw" fields in configuration file.
