/*
 * main file for HLS apache module
 * Copyright (c) 2012-2013 Voicebase Inc.
 *
 * Author: Alexander Ustinov
 * email: alexander@voicebase.com
 *
 * This file is the part of the mod_hls apache module
 *
 * This program is free software, distributed under the terms of
 * the GNU Lesser General Public License version 3. See the LICENSE file
 * at the top of the source tree.
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"
#include "util_script.h"

#include <curl/curl.h>
#include "cJSON.h"

#include "apr_strings.h"
#include "mod_conf.h"

#include <stdio.h>

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>

const char sc_filter_name[] = "SightCall";
const char SC_HANDLER_NAME[] = "SIGHTCALL";
/*
 * Declare ourselves so the configuration routines can find and know us.
 * We'll fill it in at the end of the module.
 */
module AP_MODULE_DECLARE_DATA sc_module;


typedef struct context_t{
	char 	audio_buffer[32000];
	char 	video_buffer[200000];


	char* 	buffer;
	int 	buffer_size;

	int 	buffer_pos;
	int 	sent;

	int 	pts;
	int 	prev_pts;

	cJSON* 	cfg;
	int 	segment;
	int 	segment_duration; //in milliseconds
	char* 	stream_name;
	int 	eos;
	AVFormatContext* format_ctx;
} context_t;

typedef struct buf_t{
	int 	pos;
	char* 	buf;
	int 	buf_size;
} buf_t;

static CURLcode curl_post_segment(
								const char* vb_api_url,
								const char* version,
								const char* apikey,
								const char* password,
								const char* action,
								const char* callID,
								const char* segmentNumber,
								const char* finalSegment,
								const char* rtCallbackURL,
								const char* content_name,
								const char* content_buff,
								long content_size,
								const char* pub,
								const char* title,
								const char* time_str,
								const char* desc,
								const char* lang,
								const char* sourceUrl,
								const char* recordedDate,
								const char* externalId,
								const char* ownerId,
								const char* autoCreate,
								const char* humanRush,
								const char* transcriptType,

								char* status_str,
								int status_max_size);

static size_t RecvCallBack ( char *ptr, size_t size, size_t nmemb, char *data ) {
	struct buf_t* buf = (struct buf_t*)data;
	if (buf->pos + size*nmemb < buf->buf_size){
		memcpy(&buf->buf[buf->pos],ptr, size*nmemb);
		buf->pos += size*nmemb;
	}

	return size * nmemb;
}


int check_exist(request_rec *r, const char* filename){
	int rc;
	apr_finfo_t finfo;
	int exists;
	rc = apr_stat(&finfo, filename, APR_FINFO_MIN, r->pool);
	if (rc == APR_SUCCESS) {
		exists = ( (finfo.filetype != APR_NOFILE) &&  !(finfo.filetype & APR_DIR) );
		if (exists)
			return finfo.size;
	}
	return -1;
}


cJSON* load_config(request_rec* r, char* config_file){
	int config_file_size = check_exist(r, config_file);
	if (config_file_size > 0){
		char* data = apr_palloc(r->pool, config_file_size);
		cJSON* res = cJSON_Parse(data);
		return res;
	}
	return NULL;
}

int get_safe_integer(cJSON* obj, char* name, int default_val){
	if (obj){
		cJSON* f = cJSON_GetObjectItem(obj, name);
		if (f){
			return f->valueint;
		}
	}
	return default_val;
}

const char* get_safe_string(cJSON* obj, char* name, char* default_val){
	if (obj){
		cJSON* f = cJSON_GetObjectItem(obj, name);
		if (f){
			return f->valuestring;
		}
	}
	return default_val;
}

const char *get_time(){
	return "00:00:00";
}

int send_segment(struct context_t* ctx, char* data, int len){
	char segmentNumber[12];
	char status_str[1024];
	char content_name[1024];

	const char* vb_api_url 		= get_safe_string(ctx->cfg, "API_URL", NULL);
	const char* version 		= get_safe_string(ctx->cfg, "Version", NULL);
	const char* apikey 			= get_safe_string(ctx->cfg, "Key", NULL);
	const char* password 		= get_safe_string(ctx->cfg, "pw", NULL);
	const char* pub 			= get_safe_string(ctx->cfg, "public", NULL);
	const char* rtCallbackURL   = get_safe_string(ctx->cfg, "rtCallBackURL", NULL);
	const char* transcriptType  = get_safe_string(ctx->cfg, "transcriptType", "machine");
	const char* time_str 		= get_time();
	const char* desc 		 	= get_safe_string(ctx->cfg, "description", NULL);
	const char* lang 		 	= get_safe_string(ctx->cfg, "language", NULL);
	const char* sourceUrl 	 	= get_safe_string(ctx->cfg, "sourceURL", NULL);
	const char* recordedDate 	= get_safe_string(ctx->cfg, "recordedDate", NULL);
	const char* externalId 	 	= get_safe_string(ctx->cfg, "externalID", NULL);
	const char* ownerId		 	= get_safe_string(ctx->cfg, "ownerID", NULL);
	const char* autoCreate 	 	= get_safe_string(ctx->cfg, "autoCreate", NULL);
	const char* humanRush 	 	= get_safe_string(ctx->cfg, "humanRush", NULL);

	snprintf(segmentNumber, sizeof(segmentNumber), "%d", ctx->segment );
//	itoa(segmentNumber, ctx->segment, 10);

	snprintf(content_name, sizeof(content_name), "%s.webm", ctx->stream_name);

	if (vb_api_url && version && apikey && password && pub && rtCallbackURL && transcriptType &&
			time_str && desc && lang && sourceUrl && recordedDate && externalId && ownerId	&&  autoCreate && humanRush)
	{
		if (curl_post_segment( vb_api_url,
							"1.1",
							apikey,
							password,
							"uploadMedia",
							ctx->stream_name,//			const char* callID,
							segmentNumber,
							len == 0 ? "true" : "false",// 			const char* finalSegment,
							rtCallbackURL,
							content_name,
							ctx->buffer,
							ctx->buffer_size,
							pub,
							ctx->stream_name,
							time_str,
							desc,
							lang,
							sourceUrl,
							recordedDate,
							externalId,
							ownerId,
							autoCreate,
							humanRush,
							transcriptType,
							status_str,
							sizeof(status_str)) ==  CURLE_OK){
			++ctx->segment;
		}else{
	//		printf error;
		}
	}else{
	//	printf error
	}
}

int context_init(request_rec* r, char* config, struct context_t* ctx, char* stream_name){
	ctx->buffer_pos 	= 0;
	ctx->sent 			= 0;
	ctx->pts 			= 0;
	ctx->prev_pts 		= 0;
	ctx->segment_duration = 120000;
	ctx->segment		= 0;
	ctx->eos			= 0;
	ctx->cfg 			= load_config(r, config);
	ctx->buffer_size 	= get_safe_integer(ctx->cfg, "BufferSize", 1000000);
	ctx->buffer 		= apr_palloc(r->connection->pool, ctx->buffer_size);
	ctx->stream_name	= apr_palloc(r->connection->pool, strlen(stream_name)+1);
	strcpy(ctx->stream_name, stream_name);
	return 0;
}

apr_status_t context_close(void* ctx){

	struct context_t* context = (context_t*)ctx;

	send_segment(context, NULL, 0);
	if (context->cfg){
		cJSON_Delete(context->cfg);
		context->cfg = NULL;
	}

	return APR_SUCCESS;
}

/* add a video output stream */
static AVStream *add_video_stream(AVFormatContext *oc, enum AVCodecID codec_id, int bitrate, int width, int height, int fps, int gop_size, int pix_fmt, int profile, int level, int buffer_size)
{
	AVCodecContext *c;
	AVStream *st;

	st = avformat_new_stream(oc, 0);
	if (!st) {
		fprintf(stderr, "Could not alloc stream\n");
		return NULL;
	}

	c = st->codec;
	c->codec_id = codec_id;
	c->codec_type = AVMEDIA_TYPE_VIDEO;

	/* put sample parameters */
	c->bit_rate 		= bitrate;
	c->pkt_timebase.num = 1;
	c->pkt_timebase.den = fps;


	/* resolution must be a multiple of two */
	c->width 		= width;
	c->height 		= height;
	c->coded_width	= width;
	c->coded_height = height;

	/* time base: this is the fundamental unit of time (in seconds) in terms
	of which frame timestamps are represented. for fixed-fps content,
	timebase should be 1/framerate and timestamp increments should be
	identically 1. */
	c->time_base.den = fps;
	c->time_base.num = 1;

	c->gop_size		= gop_size;
	c->ticks_per_frame = 1;
	c->flags		= 0;
	c->flags2		= 0;
	c->rc_buffer_size = buffer_size;
	c->extradata_size = 0;

	if (c->rc_buffer_size == 0){
		c->rc_buffer_size = 90000000;
	}


	st->discard 		= AVDISCARD_NONE;
	st->need_parsing 	= AVSTREAM_PARSE_FULL;
	st->start_time		= 0;
	st->time_base		= c->time_base;
	st->cur_dts 		= 0;


	// some formats want stream headers to be separate
	if(oc->oformat->flags & AVFMT_GLOBALHEADER)
		c->flags |= CODEC_FLAG_GLOBAL_HEADER;

	return st;
}

/* add a video output stream */
static AVStream *add_audio_stream(AVFormatContext *oc, enum AVCodecID codec_id, int bitrate, int sample_rate, int channels)
{
	AVCodecContext *c;
	AVStream *st;

	st = avformat_new_stream(oc, 0);
	if (!st) {
		fprintf(stderr, "Could not alloc stream\n");
		return NULL;
	}

	c = st->codec;
	c->codec_id = codec_id;
	c->codec_type = AVMEDIA_TYPE_AUDIO;
	//c->codec = avcodec_find_decoder(codec_id);
	//c->codec_tag =

	/* put sample parameters */
	c->bit_rate 	= bitrate;
	c->pkt_timebase.num = 1;
	c->pkt_timebase.den = sample_rate;

	/* time base: this is the fundamental unit of time (in seconds) in terms
	of which frame timestamps are represented. for fixed-fps content,
	timebase should be 1/framerate and timestamp increments should be
	identically 1. */
	c->time_base = c->pkt_timebase;

	c->sample_fmt  =  AV_SAMPLE_FMT_FLTP;
	c->sample_rate = sample_rate;
	c->channels	   = channels;
	c->channel_layout = av_get_default_channel_layout(channels);
//	c->strict_std_compliance = FF_COMPLIANCE_EXPERIMENTAL; /* AAC */
	c->extradata_size = 0;

	st->start_time		= 0;
	st->time_base		= c->pkt_timebase;
	st->cur_dts 		= 0;

	// some formats want stream headers to be separate
	if(oc->oformat->flags & AVFMT_GLOBALHEADER)
		c->flags |= CODEC_FLAG_GLOBAL_HEADER;

	return st;
}

int CloseOutputContainer(AVFormatContext* OutFmtCtx, uint8_t **buffer){
	av_write_trailer(OutFmtCtx);
	 /* free the streams */
	for(int i = 0; i < OutFmtCtx->nb_streams; i++) {
		av_freep(&OutFmtCtx->streams[i]->codec);
		av_freep(&OutFmtCtx->streams[i]);
	}

	if (!(OutFmtCtx->oformat->flags & AVFMT_NOFILE)) {
		/* close the output file */
		int size = avio_close_dyn_buf(OutFmtCtx->pb, buffer);
		av_free(OutFmtCtx);
		return size;
	}

	/* free the stream */
	av_free(OutFmtCtx);
	return 0;
}

int CreateOutputContainer(AVFormatContext** OutFmtCtx){
	AVOutputFormat *fmt;
	AVFormatContext *oc;

	char* out_format_name = NULL;
	out_format_name = "webm";
	if (out_format_name){
		fmt = av_guess_format(out_format_name, NULL, NULL);
		if (!fmt) {
			fprintf(stderr, "Could not find suitable output format for format %s\n", out_format_name);
			return 0;
		}
	}
//	else{
//		fmt = av_guess_format(NULL, filename, NULL);
//		if (!fmt) {
//			fprintf(stderr, "Could not find suitable output format\n");
//			return false;
//		}
//	}

/* allocate the output media context */
	oc = avformat_alloc_context();
	if (!oc) {
		fprintf(stderr, "Memory error\n");
		return 0;
	}
	oc->oformat = fmt;
//	snprintf(oc->filename, sizeof(oc->filename), "%s", filename);
	oc->filename[0] =0;
/* add the audio and video streams using the default format codecs and initialize the codecs */
	AVStream* video_st = add_video_stream(oc, AV_CODEC_ID_VP8, 400000, 640, 360, 25, 12, AV_PIX_FMT_YUV420P,  0,0, 400000);
	AVStream* audio_st = add_audio_stream(oc, AV_CODEC_ID_OPUS, 64000, 48000, 1);

	//fmt->flags |= AVFMT_TS_NONSTRICT;

	if (!(fmt->flags & AVFMT_NOFILE)) {
		if (avio_open_dyn_buf(&oc->pb) < 0) {
			fprintf(stderr, "Could not open memory stream\n");
			return 0;
		}
	}
	/* set the output parameters (must be done even if no
		parameters). */
	if (avformat_write_header(oc, NULL) < 0) {
		fprintf(stderr, "Invalid output format parameters\n");
		return 0;
	}

//	av_dump_format(oc, 0, NULL, 1);
	*OutFmtCtx = oc;
	return 1;
}

int write_packet(AVFormatContext* OutFmtCtx, AVPacket* packet){
	/* write the compressed frame in the media file */
	if (av_interleaved_write_frame(OutFmtCtx, packet) != 0){
		fprintf(stderr, "Error while writing frame\n");
		return 0;
	}
	return 1;
}

void write_video(uint8_t* buffer, int len, int pts, int stream_index, AVFormatContext* ctx){
	AVPacket packet;
	memset(&packet, 0, sizeof(packet));

	packet.data = buffer;

	packet.size = len;
	packet.stream_index = stream_index;
	packet.pts = packet.dts = pts + 5;
	write_packet(ctx, &packet);
}

void write_audio(uint8_t* buffer, int len, int pts, int stream_index, AVFormatContext* ctx){
	AVPacket packet;
	memset(&packet, 0, sizeof(packet));

	packet.data = buffer;
	packet.size = len;
	packet.stream_index = stream_index;
	packet.pts = packet.dts = pts;
	write_packet(ctx, &packet);
}


int process_data(request_rec* r, struct context_t* ctx, char* data, int len){

	if (!ctx->format_ctx){
		 if (!CreateOutputContainer(&ctx->format_ctx)){
		    	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Can't create memory container");
		 }
	}
	if (!ctx->eos){
		memcpy(&ctx->buffer[ctx->buffer_pos], data, len);
		ctx->buffer_pos += len;

		data = &ctx->buffer[0];
		len  = ctx->buffer_pos;

	}


	while(!ctx->eos){
		if (len < 1 + 4 + 4){
			break;
		}
		unsigned int type = data[0];
		unsigned int index = ((unsigned int*)&data[1])[0];
		unsigned int clen = ((unsigned int*)&data[1+4])[0];

//			fprintf(stderr, "type= %d, index=%d, len = %d\n", type, index, len);
		if ( len + 1 + 4 + 4 < clen){
			break;
		}

		data += 1+4+4;

		switch(type){
			case 0x00://control;
				{
					int cc = data[0];
					if (cc == 0xFF)
						ctx->eos = 1;
				}
				break;
			case 0x80://audio
				//move_to_file(fin,fout, len);

				write_audio(data, clen, ctx->pts, 1, ctx->format_ctx);
				ctx->pts += 20;
				break;
			case 0x90://video

				if (data[0] & 0x01 == 0){ //I frame
					if (ctx->pts - ctx->prev_pts > ctx->segment_duration){
						uint8_t* buffer = NULL;
						int stream_len = CloseOutputContainer(ctx->format_ctx, &buffer);

						if (stream_len > 0 && buffer){
							send_segment(ctx, buffer, stream_len);
							av_free(buffer);
						}
						ctx->format_ctx = NULL;
						if (!CreateOutputContainer(&ctx->format_ctx)){
							ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Can't create memory container");
						}
						ctx->prev_pts = ctx->pts;
					}
				}

				write_video(data, clen, ctx->pts, 0, ctx->format_ctx);

				break;
		}
		data += clen;
		len  -= 1 + 4 + 4 + clen;
	}

	if ( data != ctx->buffer && len > 0){
		memmove(ctx->buffer, data, len);
		ctx->buffer_pos = len;
	} else
		ctx->buffer_pos = 0;


	if (ctx->eos && ctx->format_ctx != NULL){
		uint8_t* buffer = NULL;
		int stream_len = CloseOutputContainer(ctx->format_ctx, &buffer);
		if (stream_len > 0 && buffer){
			send_segment(ctx, buffer, stream_len);
			av_free(buffer);
		}
	}

	return 1;
}

void split_file_and_path(char* access_document, char* config_file, char* stream_name){
	int t = strlen(access_document) - 1;
	while(t >= 0 && access_document[t] != '/')
		--t;
	strcpy(config_file, access_document);

	if (t >= 0){
		config_file[t] = 0;
		strcpy(stream_name, config_file + t + 1);
	}
}


double get_clock(){
	struct timeval ts;
	gettimeofday(&ts, NULL);
	return ts.tv_sec + (double)(ts.tv_usec) / 1000000.0;
}

char* get_arg_value(request_rec * r, char* args, char* key){
	int i,j;
	int args_len = strlen(args);
	int key_len= strlen(key);
	char* result = apr_pcalloc(r->pool, args_len + 1);
	int level = 0;
	memset(result, 0, args_len + 1);

	for(i = 0; i < args_len; ++ i){
		int found = 0;
		if (i == 0){
			found = (strncmp(&args[ i ], key, key_len) == 0) ? 1 : 0;
		}else{
			if (args[i - 1] == '&'){
				found = (strncmp(&args[ i ], key, key_len) == 0) ? 1 : 0;
			}
		}
		if (found){
			j = 0;
			i+=key_len+1;
			if (i + j + 3 < args_len && args[i+j] == '%' && args[i+j+1] == '2' && args[i+j+2] == '2')
				i+=3;

			while ( i + j < args_len && args[i+j] != '&'){
				result[j] = args[i+j];
				++j;
			}

			if (j > 3 && result[j-3] == '%' && result[j-2] == '2' && result[j-1] == '2'){
				j-=3;
				result[j] =0 ;
			}
			break;
		}

	}

	return result;
}

static CURLcode curl_post_segment(
								const char* vb_api_url,
								const char* version,
								const char* apikey,
								const char* password,
								const char* action,
								const char* callID,
								const char* segmentNumber,
								const char* finalSegment,
								const char* rtCallbackURL,
								const char* content_name,
								const char* content_buff,
								long content_size,
								const char* pub,
								const char* title,
								const char* time_str,
								const char* desc,
								const char* lang,
								const char* sourceUrl,
								const char* recordedDate,
								const char* externalId,
								const char* ownerId,
								const char* autoCreate,
								const char* humanRush,
								const char* transcriptType,

								char* status_str,
								int status_max_size){
	CURL *curl;
	CURLcode res;
	struct curl_httppost *formpost=NULL;
	struct curl_httppost *lastptr=NULL;

	struct buf_t buf;
	CURLFORMcode form_res;

	buf.pos = 0;
	buf.buf = status_str;
	buf.buf_size = status_max_size;
//	ast_mutex_lock(&curl_lock);

#define ADD_FORM_DATA(X, VAL) if (VAL) { form_res = curl_formadd(&formpost,  &lastptr,  CURLFORM_COPYNAME, X, CURLFORM_COPYCONTENTS, VAL,  CURLFORM_END); 	}

	ADD_FORM_DATA("version", 		version);
	ADD_FORM_DATA("apikey", 		apikey);
	ADD_FORM_DATA("password", 		password);
	ADD_FORM_DATA("action", 		action);
	ADD_FORM_DATA("callID", 		callID);
	ADD_FORM_DATA("startTime", 		time_str);
	ADD_FORM_DATA("segmentNumber", 	segmentNumber);
	ADD_FORM_DATA("finalSegment", 	finalSegment);
	ADD_FORM_DATA("rtCallbackUrl", 	rtCallbackURL);
	ADD_FORM_DATA("transcriptType", transcriptType);
	ADD_FORM_DATA("public", 		pub);
	ADD_FORM_DATA("title", 			title);
	ADD_FORM_DATA("desc", 			desc);
	ADD_FORM_DATA("lang", 			lang);
	ADD_FORM_DATA("sourceUrl", 			sourceUrl);
	ADD_FORM_DATA("recordedDate", 			recordedDate);
	ADD_FORM_DATA("externalId", 			externalId);
	ADD_FORM_DATA("ownerId", 			ownerId);
	ADD_FORM_DATA("autoCreate", 			autoCreate);
	ADD_FORM_DATA("humanRush", 			humanRush);

#undef ADD_FORM_DATA

	form_res = curl_formadd(&formpost,
	               &lastptr,
	               CURLFORM_COPYNAME, "file",
	               CURLFORM_BUFFER, 		content_name,
	               CURLFORM_BUFFERPTR, 		content_buff,
	               CURLFORM_BUFFERLENGTH, 	content_size,
	               CURLFORM_END);

//	ast_log(LOG_NOTICE, "content name = %s, content size = %d, content_ptr=0x%X\n", content_name, (int)content_size, (int)content_buff);


//	ast_log(LOG_NOTICE, "11 = %d\n", (int)form_res);


//	ast_log(LOG_NOTICE, "13 = %d\n", (int)form_res);

	/* get a curl handle */
	curl = curl_easy_init();
	if(curl) {
		/* First set the URL that is about to receive our POST. This URL can
		   just as well be a https:// URL if that is what should receive the
		   data. */
		res = curl_easy_setopt(curl, CURLOPT_URL, vb_api_url);
	//	ast_log(LOG_NOTICE, "a = %d\n", (int)res);
		/* Now specify the POST data */

		res = curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
	//	ast_log(LOG_NOTICE, "b = %d\n", (int)res);
	//	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1 );
		res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, RecvCallBack);
	//	ast_log(LOG_NOTICE, "c = %d\n", (int)res);

		res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
	//	ast_log(LOG_NOTICE, "d = %d\n", (int)res);

		/* Perform the request, res will get the return code */
		res = curl_easy_perform(curl);
		/* Check for errors */
//		if(res != CURLE_OK)
//			ast_log(LOG_NOTICE, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

		if (buf.pos > 0 && buf.pos < buf.buf_size){
			buf.buf[buf.pos] = 0;
		} else{
			buf.buf[0] = 0;
		}

		curl_formfree(formpost);
		/* always cleanup */
		curl_easy_cleanup(curl);
	}else{
//	    ast_log(LOG_NOTICE, "Failed to do curl_easy_init()\n");
	}
//	ast_mutex_unlock(&curl_lock);
	return res;
}

/* handle the PUT method */
static int sc_method_put(request_rec *r)
{
    int resource_state;

    const char *body;

    int has_range;
    apr_off_t range_start;
    apr_off_t range_end;
    apr_status_t rc;

    {
        apr_bucket_brigade *bb;
        apr_bucket *b;
        int seen_eos = 0;
        int doc_path_len = strlen(ap_context_document_root(r)) + strlen(r->uri) + 1;
    	char* access_document = apr_palloc(r->pool, doc_path_len);
    	char* config_file = apr_palloc(r->pool, doc_path_len);
    	char* stream_name = apr_palloc(r->pool, doc_path_len);

    	//need to get better way to get account info
    	strcpy(access_document, ap_context_document_root(r));
    	strcat(access_document, r->uri);

    	split_file_and_path(access_document, config_file, stream_name);

     	context_t* ctx =  NULL;

    	rc = apr_pool_userdata_get((void**)&ctx, access_document,r->connection->pool);
    	if (rc != APR_SUCCESS || ctx == NULL){
    		ctx = apr_palloc(r->pool, sizeof(context_t));
    		context_init(r, config_file, ctx, stream_name);
    		rc = apr_pool_userdata_set(ctx, access_document, context_close, r->connection->pool);
    	}

    	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: 1 url =%s",  access_document);


        bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: 2");
        do {


            rc = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                                APR_BLOCK_READ, 8000);
//            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: 3");
            if (rc != APR_SUCCESS) {

                break;
            }
//            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: 4");
            for (b = APR_BRIGADE_FIRST(bb);
                 b != APR_BRIGADE_SENTINEL(bb);
                 b = APR_BUCKET_NEXT(b))
            {
                const char *data;
                apr_size_t len;

                if (APR_BUCKET_IS_EOS(b)) {
                    seen_eos = 1;
                    break;
                }

                if (APR_BUCKET_IS_METADATA(b)) {
                    continue;
                }

				rc = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);

				seen_eos = process_data(r, ctx, (char*)data, len);

//				ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: readlen = %d", (int)len);

				if (rc != APR_SUCCESS) {
					break;
				}

            }
 //           ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: 5");
            apr_brigade_cleanup(bb);
        } while (!seen_eos);
  //      ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: 6");
        apr_brigade_destroy(bb);

    }


    return OK;
}
/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Now we declare our content handlers, which are invoked when the server   */
/* encounters a document which our module is supposed to have a chance to   */
/* see.  (See mod_mime's SetHandler and AddHandler directives, and the      */
/* mod_info and mod_status examples, for more details.)                     */
/*                                                                          */
/* Since content handlers are dumping data directly into the connection     */
/* (using the r*() routines, such as rputs() and rprintf()) without         */
/* intervention by other parts of the server, they need to make             */
/* sure any accumulated HTTP headers are sent first.  This is done by       */
/* calling send_http_header().  Otherwise, no header will be sent at all,   */
/* and the output sent to the client will actually be HTTP-uncompliant.     */
/*--------------------------------------------------------------------------*/
/*
 * Sample content handler.  All this does is display the call list that has
 * been built up so far.
 *
 * The return value instructs the caller concerning what happened and what to
 * do next:
 *  OK ("we did our thing")
 *  DECLINED ("this isn't something with which we want to get involved")
 *  HTTP_mumble ("an error status should be reported")
 */
int sc_handler(request_rec *r, int lookup_uri)
{

	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Handler start");

	r->allowed = 0
		| (AP_METHOD_BIT << M_PUT)
		| (AP_METHOD_BIT << M_POST);

	 if (r->method_number == M_PUT || r->method_number == M_POST) {

		return sc_method_put(r);
	}

    return DECLINED;
}


/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Which functions are responsible for which hooks in the server.           */
/*                                                                          */
/*--------------------------------------------------------------------------*/
/*
 * Each function our module provides to handle a particular hook is
 * specified here.  The functions are registered using
 * ap_hook_foo(name, predecessors, successors, position)
 * where foo is the name of the hook.
 *
 * The args are as follows:
 * name         -> the name of the function to call.
 * predecessors -> a list of modules whose calls to this hook must be
 *                 invoked before this module.
 * successors   -> a list of modules whose calls to this hook must be
 *                 invoked after this module.
 * position     -> The relative position of this module.  One of
 *                 APR_HOOK_FIRST, APR_HOOK_MIDDLE, or APR_HOOK_LAST.
 *                 Most modules will use APR_HOOK_MIDDLE.  If multiple
 *                 modules use the same relative position, Apache will
 *                 determine which to call first.
 *                 If your module relies on another module to run first,
 *                 or another module running after yours, use the
 *                 predecessors and/or successors.
 *
 * The number in brackets indicates the order in which the routine is called
 * during request processing.  Note that not all routines are necessarily
 * called (such as if a resource doesn't have access restrictions).
 * The actual delivery of content to the browser [9] is not handled by
 * a hook; see the handler declarations below.
 */


static void sc_register_hooks(apr_pool_t *p)
{
//    ap_hook_handler(sc_handler, NULL, NULL, APR_HOOK_MIDDLE);
//	ap_register_input_filter(sc_filter_name, sc_filter, NULL, AP_FTYPE_CONTENT_SET);
//	ap_register_output_filter(sc_filter_name, sc_filter_out, NULL, AP_FTYPE_CONTENT_SET);

	av_register_all();
	ap_hook_quick_handler(sc_handler, NULL, NULL, APR_HOOK_LAST);
}

const char* hls_option_audio_encoding_bitrate(cmd_parms *cmd, void *cfg, const char *arg){
	//set_encode_audio_bitrate(atoi(arg));

	return NULL;
}

const char* hls_option_audio_encoding_codec(cmd_parms *cmd, void *cfg, const char *arg){
//	if(!strcasecmp(arg, "mp3")){
//		set_encode_audio_codec(1);
//	}
//	set_encode_audio_codec(1);

	return NULL;
}

const char* hls_option_logo_filename(cmd_parms *cmd, void *cfg, const char *arg){
//	set_logo_filename(arg);
	return NULL;
}

const char* hls_option_allow_http(cmd_parms *cmd, void *cfg, const char *arg){
//	if(!strcasecmp(arg, "yes")) set_allow_http(1);
//	    else set_allow_http(0);
	return NULL;
}

const char* hls_option_allow_redirect(cmd_parms *cmd, void *cfg, const char *arg){
//	if(!strcasecmp(arg, "yes")) set_allow_redirect(1);
//	    else set_allow_redirect(0);
	return NULL;
}


const char* hls_option_allow_wav(cmd_parms *cmd, void *cfg, const char *arg){
//	if(!strcasecmp(arg, "yes")) set_allow_wav(1);
//	    else set_allow_wav(0);
	return NULL;
}

const char* hls_option_allow_mp3(cmd_parms *cmd, void *cfg, const char *arg){
//	if(!strcasecmp(arg, "yes")) set_allow_mp3(1);
//	    else set_allow_mp3(0);
	return NULL;
}

const char* hls_option_data_path(cmd_parms *cmd, void *cfg, const char *arg){
//	set_data_path(arg);
	return NULL;
}

const char* hls_option_segment_length(cmd_parms *cmd, void *cfg, const char *arg){
//	set_segment_length(atoi(arg));
	return NULL;
}

const char* hls_option_log_level(cmd_parms *cmd, void *cfg, const char *arg){
//	set_log_level(atoi(arg));
	return NULL;
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* All of the routines have been declared now.  Here's the list of          */
/* directives specific to our module, and information about where they      */
/* may appear and how the command parser should pass them to us for         */
/* processing.  Note that care must be taken to ensure that there are NO    */
/* collisions of directive names between modules.                           */
/*                                                                          */
/*--------------------------------------------------------------------------*/
/*
 * List of directives specific to our module.
 */
static const command_rec sc_cmds[] =
{
//	AP_INIT_TAKE1(  "AudioEncodingBitrate", hls_option_audio_encoding_bitrate, NULL, OR_OPTIONS, "Audio bitrate for internal audio encoder (in kbps)" ),
//	AP_INIT_TAKE1(  "AudioEncodingCodec",   hls_option_audio_encoding_codec,   NULL, OR_OPTIONS, "Audio codec used for internal encoding. Currently support only one codec 1 - mp3" ),
//	AP_INIT_TAKE1(  "LogoFilename",         hls_option_logo_filename,  		   NULL, OR_OPTIONS, "H264 Video file in AnnexB form" ),
//	AP_INIT_TAKE1(  "AllowWAV", 			hls_option_allow_wav, 		  	   NULL, OR_OPTIONS, "Allow WAV files to process" ),
//	AP_INIT_TAKE1(  "AllowMP3", 			hls_option_allow_mp3, 		  	   NULL, OR_OPTIONS, "Allow MP3 files to process" ),
//	AP_INIT_TAKE1(  "AllowHTTP", 			hls_option_allow_http, 		  	   NULL, OR_OPTIONS, "Allow HTTP routing" ),
//	AP_INIT_TAKE1(  "SegmentLength", 		hls_option_segment_length, 	 	   NULL, OR_OPTIONS, "Segment length in seconds" ),
//	AP_INIT_TAKE1(  "AllowRedirect", 		hls_option_allow_redirect, 	 	   NULL, OR_OPTIONS, "Allow redirect for HTTP request to remote content" ),
//	AP_INIT_TAKE1(  "HLSLogLevel", 			hls_option_log_level, 		 	   NULL, OR_OPTIONS, "Setup log level for HLS plugin" ),
//	AP_INIT_TAKE1(  "HLSDataPath", 			hls_option_data_path, 		 	   NULL, OR_OPTIONS, "Data path for HLS plugin" ),


    {NULL}
};
/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Finally, the list of callback routines and data structures that provide  */
/* the static hooks into our module from the other parts of the server.     */
/*                                                                          */
/*--------------------------------------------------------------------------*/
/*
 * Module definition for configuration.  If a particular callback is not
 * needed, replace its routine name below with the word NULL.
 */
module AP_MODULE_DECLARE_DATA sc_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,    /* per-directory config creator */
    NULL,     /* dir config merger */
    NULL, /* server config creator */
    NULL,  /* server config merger */
    sc_cmds,                 /* command table */
    sc_register_hooks,       /* set up other request processing hooks */
};
