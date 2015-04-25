/*
 * main file for SightCall apache module
 * Copyright (c) 2012-2013 Voicebase Inc.
 *
 * Author: Alexander Ustinov, Nikolay Pomazan
 * email: alexander@voicebase.com
 *
 *
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
#include <libavutil/channel_layout.h>

const char sc_filter_name[] = "SightCall";
const char SC_HANDLER_NAME[] = "SIGHTCALL";

char time_buffer[16];

/*
 * Declare ourselves so the configuration routines can find and know us.
 * We'll fill it in at the end of the module.
 */
module AP_MODULE_DECLARE_DATA sc_module;


typedef struct context_t{
	char 	audio_buffer[100000];
	char 	video_buffer[1000000];


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
	int 	n_iframes;
	char* 	cfg_data;
	int 	no_video;
	AVFormatContext* format_ctx;
	request_rec* r;
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

cJSON* load_config( request_rec* r, context_t* ctx, char* config_file){
	int config_file_size = check_exist(r,  config_file);
	if (config_file_size > 0){
		ctx->cfg_data = apr_palloc(r->pool, config_file_size);
		apr_file_t* f = NULL;
		apr_file_open (&f, config_file, APR_READ, APR_OS_DEFAULT, r->pool);

		if (f){
			apr_size_t nbytes = config_file_size;
			apr_file_read(f, ctx->cfg_data, &nbytes);
			apr_file_close(f);
		}
		cJSON* res = cJSON_Parse(ctx->cfg_data );
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

const char *get_time(int pts){

	int hours = pts / (60*60*1000);
	int mins = (pts - hours * 60 *60 * 1000)/ (60 * 1000);
	int secs = (pts - hours * 60 *60* 1000 - mins * 60 * 1000) / 1000;
	sprintf(time_buffer, "%02d:%02d:%02d.%03d", hours, mins, secs, pts % 1000);
	return time_buffer;
}

int send_segment(request_rec* r, struct context_t* ctx, char* data, int len){
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
	const char* time_str 		= get_time(ctx->prev_pts);
	const char* desc 		 	= get_safe_string(ctx->cfg, "description", NULL);
	const char* lang 		 	= get_safe_string(ctx->cfg, "language", NULL);
	const char* sourceUrl 	 	= get_safe_string(ctx->cfg, "sourceURL", NULL);
	const char* recordedDate 	= get_safe_string(ctx->cfg, "recordedDate", NULL);
	const char* externalId 	 	= get_safe_string(ctx->cfg, "externalID", NULL);
	const char* ownerId		 	= get_safe_string(ctx->cfg, "ownerID", NULL);
	const char* autoCreate 	 	= get_safe_string(ctx->cfg, "autoCreate", NULL);
	const char* humanRush 	 	= get_safe_string(ctx->cfg, "humanRush", NULL);

	snprintf(segmentNumber, sizeof(segmentNumber), "%d", ctx->segment );

	snprintf(content_name, sizeof(content_name), "%s.webm", ctx->stream_name);
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: content name=%s, data size=%d\n", content_name, (int)len);

	if (vb_api_url && version && apikey && password )
	{
		if (curl_post_segment( vb_api_url,
							"1.1",
							apikey,
							password,
							"uploadMedia",
							ctx->stream_name,//			const char* callID,
							segmentNumber,
							ctx->eos ? "true" : "false",// 			const char* finalSegment,
							rtCallbackURL,
							content_name,
							data,
							len,
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
			if (r){
				ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Post segment %d, eos= %d, status=%s\n", ctx->segment, ctx->eos, status_str);
			}
			++ctx->segment;
		}else{
			ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Can't send the segment %d, eos= %d, status=%s\n", ctx->segment, ctx->eos, status_str);

		}
	}else{
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Not specified vb_api_url or version or apikey or password");
	}
}
int context_init(request_rec* r, char* config, struct context_t* ctx, char* stream_name){
	int len;
	ctx->buffer_pos 	= 0;
	ctx->sent 			= 0;
	ctx->pts 			= 0;
	ctx->prev_pts 		= 0;
	ctx->segment		= 0;
	ctx->eos			= 0;
	ctx->n_iframes		= 0;
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Open configuration file %s", config);
	ctx->cfg 			= load_config(r, ctx, config);
	ctx->buffer_size 	= get_safe_integer(ctx->cfg, "BufferSize", 2000000);
	ctx->buffer 		= apr_palloc(r->connection->pool, ctx->buffer_size);
	ctx->stream_name	= apr_palloc(r->connection->pool, strlen(stream_name)+1);
	ctx->segment_duration = get_safe_integer(ctx->cfg, "SegmentDuration", 120000); // default chunk size is 2 min

	ctx->no_video		= strcasecmp(get_safe_string(ctx->cfg, "noVideo", "false"), "true") == 0;
	ctx->r  			= r;
	strcpy(ctx->stream_name, stream_name);
	len = strlen(ctx->stream_name);
	for(int i = 0; i < len; ++i){
		if (ctx->stream_name[i] == ':'){
			ctx->stream_name[i] = '-';
		}
	}
	return 0;
}



apr_status_t context_close( void* ctx){

	struct context_t* context = (context_t*)ctx;

	context->eos = 1;

	if (context->format_ctx == NULL){
		char* tail_filename = get_safe_string(context->cfg, "TailFile", NULL);

		char* buffer = NULL;
		int buffer_len = 0;
		FILE* f = fopen(tail_filename, "rb");
		if (f){
			fseek(f, 0, SEEK_END);
			buffer_len = ftell(f);
			fseek(f, 0, SEEK_SET);
			buffer = (char*)malloc(buffer_len);
			fread(buffer, buffer_len, 1, f);
			fclose(f);
		}

		send_segment(context->r, context, buffer, buffer_len);

		if (buffer){
			free(buffer);
		}
	}else{
		uint8_t* buffer = NULL;
		int stream_len = CloseOutputContainer(context->format_ctx, &buffer);
		if (stream_len > 0 && buffer){
			ap_log_error(APLOG_MARK, APLOG_WARNING, 0, context->r->server, "mod_sc: Output segment size %d", stream_len);

			send_segment(context->r, ctx, buffer, stream_len);
			av_free(buffer);
		}
		context->format_ctx = NULL;
	}

	if (context->cfg){
		cJSON_Delete(context->cfg);
		context->cfg = NULL;
	}

	return APR_SUCCESS;
}

/* add a video output stream */
static AVStream *add_video_stream(request_rec* r, AVFormatContext *oc, enum AVCodecID codec_id, int bitrate, int width, int height, int fps, int gop_size, int pix_fmt, int profile, int level, int buffer_size)
{
	AVCodecContext *c;
	AVStream *st;

	st = avformat_new_stream(oc, 0);
	if (!st) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "Could not alloc stream");
		return NULL;
	}

	c = st->codec;
	c->codec_id = codec_id;
	c->codec_type = AVMEDIA_TYPE_VIDEO;

	/* put sample parameters */
	c->bit_rate 		= bitrate;
//	c->pkt_timebase.num = 1;
//	c->pkt_timebase.den = fps;


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
static AVStream *add_audio_stream(request_rec* r,AVFormatContext *oc, enum AVCodecID codec_id, int bitrate, int sample_rate, int channels)
{
	AVCodecContext *c;
	AVStream *st;

	st = avformat_new_stream(oc, 0);
	if (!st) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "Could not alloc stream");
		return NULL;
	}

	c = st->codec;
	c->codec_id = codec_id;
	c->codec_type = AVMEDIA_TYPE_AUDIO;
	//c->codec = avcodec_find_decoder(codec_id);
	//c->codec_tag =

	/* put sample parameters */
	c->bit_rate 	= bitrate;
//	c->pkt_timebase.num = 1;
//	c->pkt_timebase.den = sample_rate;

	/* time base: this is the fundamental unit of time (in seconds) in terms
	of which frame timestamps are represented. for fixed-fps content,
	timebase should be 1/framerate and timestamp increments should be
	identically 1. */
	c->time_base.num = 1;// = c->pkt_timebase;
	c->time_base.den = sample_rate;

	c->sample_fmt  =  AV_SAMPLE_FMT_FLTP;
	c->sample_rate = sample_rate;
	c->channels	   = channels;
	c->channel_layout = av_get_default_channel_layout(channels);
//	c->strict_std_compliance = FF_COMPLIANCE_EXPERIMENTAL; /* AAC */
	c->extradata_size = 0;

	st->start_time		= 0;
	st->time_base		= c->time_base;
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

int CreateOutputContainer(request_rec* r,AVFormatContext** OutFmtCtx, int no_video){
	AVOutputFormat *fmt;
	AVFormatContext *oc;

	char* out_format_name = NULL;
	//we select matroska container because it supports OPUS audio codec
	out_format_name = "matroska";
	if (out_format_name){
		fmt = av_guess_format(out_format_name, NULL, NULL);
		if (!fmt) {
			ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "Could not find suitable output format for format %s", out_format_name);
			return 0;
		}
	}

	oc = avformat_alloc_context();
	if (!oc) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "Not enough memory");
		return 0;
	}
	oc->oformat = fmt;
	oc->filename[0] =0;

	/* add the audio and video streams using the default format codecs and initialize the codecs */

	if (!no_video){
		AVStream* video_st = add_video_stream(r, oc, AV_CODEC_ID_VP8, 400000, 640, 360, 25, 12, AV_PIX_FMT_YUV420P,  0,0, 400000);
	}
	AVStream* audio_st = add_audio_stream(r, oc, AV_CODEC_ID_OPUS, 64000, 48000, 1);

	if (!(fmt->flags & AVFMT_NOFILE)) {
		if (avio_open_dyn_buf(&oc->pb) < 0) {
			ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "Could not open memory stream");
			return 0;
		}
	}
	/* set the output parameters (must be done even if no
		parameters). */
	if (avformat_write_header(oc, NULL) < 0) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "Invalid output format parameters");
		return 0;
	}

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

//#define LOG_ON

int process_data(request_rec* r, struct context_t* ctx, char* data, int len){
#ifdef LOG_ON
    	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Process post, input data len=%d", len);
#endif

	if (!ctx->format_ctx){
#ifdef LOG_ON
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Creating format context");
#endif

		 if (!CreateOutputContainer(r, &ctx->format_ctx, ctx->no_video) || ctx->format_ctx == NULL){
		 	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Faile to create format context");

		 }
	}
#ifdef LOG_ON
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Current buffer size=%d, pts=%d, eos=%d", (int)ctx->buffer_pos + len, (int)ctx->pts, (int)ctx->eos);
#endif
	
	if (!ctx->eos){
		memcpy(&ctx->buffer[ctx->buffer_pos], data, len);
		ctx->buffer_pos += len;

		data = &ctx->buffer[0];
		len  = ctx->buffer_pos;
	}


	while(!ctx->eos){
		//1 byte is the packet type
		//4 bytes is the packet index
		//4 bytes is the packet length

		unsigned int type = (unsigned char)data[0];
		unsigned int index = ((unsigned int*)&data[1])[0];
		unsigned int clen = ((unsigned int*)&data[1+4])[0];
#ifdef LOG_ON
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: input data len=%d, clen=%d", (int)len, (int)clen);
#endif

		if (len < 1 + 4 + 4){
			break;
		}

		if ( len  < clen + 1 + 4 + 4){
			break;
		}

		data += 1+4+4;

#ifdef LOG_ON
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Message len=%d, type=%d", (int)clen, (int)type);
#endif

		switch(type){
			case 0x00://control;
				{
//					ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Control message");

					unsigned int cc = (unsigned char)data[0];
					if (cc == 0xFF){
						ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: found end of stream");
						ctx->eos = 1;
					}
				}
				break;
			case 0x80://audio
				if (ctx->no_video){
					if (ctx->pts - ctx->prev_pts > ctx->segment_duration){
						char* buffer = NULL;
						ctx->n_iframes = 0;
						int stream_len = CloseOutputContainer(ctx->format_ctx, &buffer);
#ifdef LOG_ON
				    		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Output segment (audio) %d", stream_len);
#endif

						if (stream_len > 0 && buffer){
							ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Output segment size(non final) %d", stream_len);

							send_segment(r, ctx, buffer, stream_len);

							av_free(buffer);
						}

						ctx->format_ctx = NULL;
						if (!CreateOutputContainer(r, &ctx->format_ctx, ctx->no_video)){
							ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Can't create memory container");
						}
						ctx->prev_pts = ctx->pts;
					}
				}
				if (ctx->n_iframes > 0 || ctx->no_video){

#ifdef LOG_ON
					ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Writing audio packet, size=%d, pts=%d", clen, ctx->pts);
#endif
					
					write_audio(data, clen, ctx->pts, ctx->no_video ? 0 : 1, ctx->format_ctx);
				}

				ctx->pts += 20;
				if (ctx->n_iframes == 0 && !ctx->no_video)
					ctx->prev_pts = ctx->pts;

				break;
			case 0x90://video
				if ((data[0] & 0x01) == 0){ //I frame
					if (ctx->pts - ctx->prev_pts > ctx->segment_duration && !ctx->no_video){
						char* buffer = NULL;
						ctx->n_iframes = 0;
						int stream_len = CloseOutputContainer(ctx->format_ctx, &buffer);
#ifdef LOG_ON
				    		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Output segment (video) %d", stream_len);
#endif

						if (stream_len > 0 && buffer){
							ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Output segment size(non final) %d", stream_len);
							send_segment(r, ctx, buffer, stream_len);

							av_free(buffer);
						}

						ctx->format_ctx = NULL;
						if (!CreateOutputContainer(r, &ctx->format_ctx, ctx->no_video)){
							ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Can't create memory container");
						}
						ctx->prev_pts = ctx->pts;
					}
					++ctx->n_iframes;
				}

				if (ctx->n_iframes > 0 && ! ctx->no_video){
					write_video(data, clen, ctx->pts, 0, ctx->format_ctx);
				}

				break;
		}
		data += clen;
		len  -= 1 + 4 + 4 + clen;
	}

	if ( len > 0){	
		if (ctx->buffer != data)
			memmove(ctx->buffer, data, len);
		ctx->buffer_pos = len;
	} else
		ctx->buffer_pos = 0;


//	if (ctx->eos && ctx->format_ctx != NULL){
//		uint8_t* buffer = NULL;
//		int stream_len = CloseOutputContainer(ctx->format_ctx, &buffer);
//		if (stream_len > 0 && buffer){
//			ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "mod_sc: Output segment size %d", stream_len);
//
//			send_segment(r, ctx, buffer, stream_len);
//			av_free(buffer);
//		}
//		ctx->format_ctx = NULL;
//	}

	if (ctx && ctx->eos)
		return APR_OS_START_USERERR;

	return APR_SUCCESS;
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

CURLcode curl_post_segment(
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

	/* get a curl handle */
	curl = curl_easy_init();
	if(curl) {
		/* First set the URL that is about to receive our POST. This URL can
		   just as well be a https:// URL if that is what should receive the
		   data. */
		res = curl_easy_setopt(curl, CURLOPT_URL, vb_api_url);
		/* Now specify the POST data */

		res = curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
		res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, RecvCallBack);
		res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);

		/* Perform the request, res will get the return code */
		res = curl_easy_perform(curl);
		/* Check for errors */

		if (buf.pos > 0 && buf.pos < buf.buf_size){
			buf.buf[buf.pos] = 0;
		} else{
			buf.buf[0] = 0;
		}

		curl_formfree(formpost);
		/* always cleanup */
		curl_easy_cleanup(curl);
	}else{
	}
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

        bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
        do {


            rc = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                                APR_BLOCK_READ, 8000);
            if (rc != APR_SUCCESS) {

                break;
            }
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

				if (rc != APR_SUCCESS) {
					break;
				}

            }
            apr_brigade_cleanup(bb);
        } while (!seen_eos);
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
