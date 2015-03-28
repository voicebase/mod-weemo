CURL_FOLDER=/usr/include/curl
TOOL=apxs2
sudo $TOOL -c -i -a -I $CURL_FOLDER -L $CURL_FOLDER/lib/.libs/ -l avformat -l avcodec -l avutil  -l curl -l pthread -l z -l m mod_sc.c cJSON.c mod_conf.c -shared

sudo /etc/init.d/apache2 restart

