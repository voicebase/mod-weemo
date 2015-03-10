struct mem_storage_t{
	char* 	buf;
	int 	buf_size;
	int 	pos;
	int 	count;
	int 	is_opened;
	int 	wav_header_size;
	char 	session_id[2048];
	char 	time_string[1024];
	int		pts;
	struct cJSON* params;
};

int create_mem_storage(struct mem_storage_t* mem_storage, const char* command_line);
int destroy_mem_storage(struct mem_storage_t* mem_storage);
int is_opened(struct mem_storage_t* mem_storage);
int put_data(struct mem_storage_t* mem_storage, struct ast_frame* frm);
int put_silence(struct mem_storage_t* mem_storage, int num_of_silence_samples);
int open_mem_storage(struct mem_storage_t* mem_storage, const char* session_id, int count, int pts);
int close_mem_storage(struct mem_storage_t* mem_storage, int last);

void get_ip_string(char* result, int max_size);

void set_vb_api_key(const char* key);
char* get_vb_api_key();

void set_vb_password(const char* pass);
char* get_vb_password();

void set_vb_public(const char* pub);
char* get_vb_public();

void set_vb_callback_url(const char* url);
char* get_vb_callback_url();

void set_vb_api_url(const char* api_url);
char* get_vb_api_url();

void set_vb_title(const char* title);
char* get_vb_title();

void set_vb_segment_duration(int duration);
int get_vb_segment_duration();

void set_vb_ip_string(const char* ip_string);
char* get_vb_ip_string();


void set_defaults();

//static char vb_time_string[1024];
