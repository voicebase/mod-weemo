FFMPEG_FOLDER=/home/alex/work/ffmpeg
CURL_FOLDER=/usr/include/curl
TOOL=apxs2
sudo $TOOL -c -i -a -I $CURL_FOLDER -L $CURL_FOLDER/lib/.libs/ -I $FFMPEG_FOLDER/ffmpeg -L $FFMPEG_FOLDER/lib -l avformat -l avcodec -l mp3lame -l vpx -l opencore-amrnb -l swscale -l opencore-amrwb -l vorbisenc -l opus -l vo-amrwbenc -l x264 -l dl -l vorbis -l ogg -l fdk-aac -l avutil -l swresample  -l curl -l rt -l idn -l pthread -l z -l m mod_sc.c cJSON.c mod_conf.c -static

#sudo apxs -i -a -c mod_sc.c 
sudo /etc/init.d/apache2 restart

