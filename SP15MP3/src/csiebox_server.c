#include "csiebox_server.h"

#include "csiebox_common.h"
#include "connect.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>

#include <sys/inotify.h>
#include <sys/mman.h>
#include <dirent.h>
#include <libgen.h>
#include <unistd.h>

#define MAX_PATHLEN 400
#define MAX_HASH 1000
#define EVENT_SIZE ( sizeof(struct inotify_event) )
#define EVENT_BUF_LEN ( 1024 * (EVENT_SIZE + 16) )

static int parse_arg(csiebox_server* server, int argc, char** argv);
static int handle_request(csiebox_server* server, int conn_fd, int _max_fd);
static int get_account_info(csiebox_server* server,  const char* user, csiebox_account_info* info);
static void login(csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void logout(csiebox_server* server, int conn_fd);
static void sync_file(csiebox_server* server, int conn_fd, csiebox_protocol_meta* meta, char *_path);
static char* get_user_homedir(csiebox_server* server, csiebox_client_info* info);
static void rm_file(csiebox_server* server, int conn_fd, csiebox_protocol_rm* rm, char *_path);
static void dl_file(int _conn_fd, char *_path);
static void dl_rm(int _conn_fd, char *_path);
static void start_traverse(csiebox_server *_server, int _conn_fd);
static int traverse_dir(csiebox_server *_server, int _conn_fd, char *_path);

void csiebox_server_init(csiebox_server** server, int argc, char** argv) {
	csiebox_server* tmp = (csiebox_server*)malloc(sizeof(csiebox_server));
	if (!tmp) {
		fprintf(stderr, "server malloc fail\n");
		return;
	}
	memset(tmp, 0, sizeof(csiebox_server));
	if (!parse_arg(tmp, argc, argv)) {
		fprintf(stderr, "Usage: %s [config file] [-d]\n", argv[0]);
		free(tmp);
		return;
	}

	int fd = server_start();
	if (fd < 0) {
		fprintf(stderr, "server fail\n");
		free(tmp);
		return;
	}
	tmp->client = (csiebox_client_info**)malloc(sizeof(csiebox_client_info*) * getdtablesize());
	if (!tmp->client) {
		fprintf(stderr, "client list malloc fail\n");
		close(fd);
		free(tmp);
		return;
	}
	memset(tmp->client, 0, sizeof(csiebox_client_info*) * getdtablesize());
	tmp->listen_fd = fd;
	*server = tmp;
}

int csiebox_server_run(csiebox_server* server) { 
	// max fd to trace
	int fdmax = server->listen_fd;
	// setup fd_sets for master and tmp
	fd_set master, read_fds;
	FD_SET(server->listen_fd, &master);
	int conn_fd, conn_len;
	struct sockaddr_in addr;
	memset( &addr, 0, sizeof(addr) );
	conn_len = sizeof(addr);
	while (1) {
		// copy master into read_fds
		read_fds = master;
		// select the valid fds
		if(select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1) {
			fprintf(stderr, "Error: Select\n");
			exit(EXIT_FAILURE);
		}
		for(int fdnow = 0 ; fdnow <= fdmax ; fdnow++) {
			// new connection
			if(FD_ISSET(fdnow, &read_fds) && fdnow == server->listen_fd) {
				conn_fd = accept(server->listen_fd, (struct sockaddr*)&addr, (socklen_t*)&conn_len);
				if(conn_fd < 0) {
					fprintf( stderr, "Error: Accept with errno: %s\n", strerror(errno) );
					exit(EXIT_FAILURE);
				}
				FD_SET(conn_fd, &master);
				if(conn_fd > fdmax)	fdmax = conn_fd;
			}
			// handle the request of connected client
			else if( FD_ISSET(fdnow, &read_fds) )
				if(handle_request(server, fdnow, fdmax) == -1)	FD_CLR(fdnow, &master);
		}
	}
	return 1;
}

void csiebox_server_destroy(csiebox_server** server) {
	csiebox_server* tmp = *server;
	*server = 0;
	if (!tmp) {
		return;
	}
	close(tmp->listen_fd);
	free(tmp->client);
	free(tmp);
}

static int parse_arg(csiebox_server* server, int argc, char** argv) {
	if (argc < 2) {
		return 0;
	}
	FILE* file = fopen(argv[1], "r");
	if (!file) {
		return 0;
	}
	fprintf(stderr, "reading config...\n");
	size_t keysize = 20, valsize = 20;
	char* key = (char*)malloc(sizeof(char) * keysize);
	char* val = (char*)malloc(sizeof(char) * valsize);
	ssize_t keylen, vallen;
	int accept_config_total = 2;
	int accept_config[2] = {0, 0};
	while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
		key[keylen] = '\0';
		vallen = getline(&val, &valsize, file) - 1;
		val[vallen] = '\0';
		fprintf(stderr, "config (%zd, %s)=(%zd, %s)\n", keylen, key, vallen, val);
		if (strcmp("path", key) == 0) {
			if (vallen <= sizeof(server->arg.path)) {
				strncpy(server->arg.path, val, vallen);
				accept_config[0] = 1;
			}
		} else if (strcmp("account_path", key) == 0) {
			if (vallen <= sizeof(server->arg.account_path)) {
				strncpy(server->arg.account_path, val, vallen);
				accept_config[1] = 1;
			}
		}
	}
	free(key);
	free(val);
	fclose(file);
	int i, test = 1;
	for (i = 0; i < accept_config_total; ++i) {
		test = test & accept_config[i];
	}
	if (!test) {
		fprintf(stderr, "config error\n");
		return 0;
	}
	return 1;
}

static int handle_request(csiebox_server* server, int conn_fd, int _max_fd) {
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	if(recv_message( conn_fd, &header, sizeof(header) ) <= 0) {
		fprintf(stderr, "logout or error\n");
		logout(server, conn_fd);
		return -1;
	}
	else {
		if (header.req.magic != CSIEBOX_PROTOCOL_MAGIC_REQ) {
			return 0;
		}
		switch (header.req.op) {
			case CSIEBOX_PROTOCOL_OP_LOGIN:
				fprintf(stderr, "login\n");
				csiebox_protocol_login req;
				if (complete_message_with_header(conn_fd, &header, &req)) {
					login(server, conn_fd, &req);
				}
				break;
			case CSIEBOX_PROTOCOL_OP_SYNC_META:
				fprintf(stderr, "sync meta\n");
				csiebox_protocol_meta meta;
				if (complete_message_with_header(conn_fd, &header, &meta)) {
					char path[MAX_PATHLEN] = ".";
					sync_file(server, conn_fd, &meta, path);
					// sync other devices with the same user
					for(int fdnow = 0 ; fdnow <= _max_fd ; fdnow++)
						if(fdnow != conn_fd && server->client[fdnow] != 0)
							if(memcmp(server->client[fdnow]->account.user, server->client[conn_fd]->account.user, USER_LEN_MAX) == 0)
								dl_file(fdnow, path);
				}
				break;
			case CSIEBOX_PROTOCOL_OP_SYNC_END:
				fprintf(stderr, "sync end\n");
				start_traverse(server, conn_fd);
				break;
			case CSIEBOX_PROTOCOL_OP_RM:
				fprintf(stderr, "rm\n");
				csiebox_protocol_rm rm;
				if (complete_message_with_header(conn_fd, &header, &rm)) {
					char path[MAX_PATHLEN] = ".";
					rm_file(server, conn_fd, &rm, path);
					// sync other devices with the same user
					for(int fdnow = 0 ; fdnow <= _max_fd ; fdnow++)
						if(fdnow != conn_fd && server->client[fdnow] != 0)
							if(memcmp(server->client[fdnow]->account.user, server->client[conn_fd]->account.user, USER_LEN_MAX) == 0)
								dl_rm(fdnow, path);
				}
				break;
			default:
				fprintf(stderr, "unknow op %x\n", header.req.op);
				break;
		}    
	}
	return 0;
}

static int get_account_info(
		csiebox_server* server,  const char* user, csiebox_account_info* info) {
	FILE* file = fopen(server->arg.account_path, "r");
	if (!file) {
		return 0;
	}
	size_t buflen = 100;
	char* buf = (char*)malloc(sizeof(char) * buflen);
	memset(buf, 0, buflen);
	ssize_t len;
	int ret = 0;
	int line = 0;
	while ((len = getline(&buf, &buflen, file) - 1) > 0) {
		++line;
		buf[len] = '\0';
		char* u = strtok(buf, ",");
		if (!u) {
			fprintf(stderr, "ill form in account file, line %d\n", line);
			continue;
		}
		if (strcmp(user, u) == 0) {
			memcpy(info->user, user, strlen(user));
			char* passwd = strtok(NULL, ",");
			if (!passwd) {
				fprintf(stderr, "ill form in account file, line %d\n", line);
				continue;
			}
			md5(passwd, strlen(passwd), info->passwd_hash);
			ret = 1;
			break;
		}
	}
	free(buf);
	fclose(file);
	return ret;
}

static void login(csiebox_server* server, int conn_fd, csiebox_protocol_login* login) {
	int succ = 1;
	csiebox_client_info* info = (csiebox_client_info*)malloc(sizeof(csiebox_client_info));
	memset(info, 0, sizeof(csiebox_client_info));
	if (!get_account_info(server, login->message.body.user, &(info->account))) {
		fprintf(stderr, "cannot find account\n");
		succ = 0;
	}
	if (succ &&
			memcmp(login->message.body.passwd_hash,
				info->account.passwd_hash,
				MD5_DIGEST_LENGTH) != 0) {
		fprintf(stderr, "passwd miss match\n");
		succ = 0;
	}

	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_LOGIN;
	header.res.datalen = 0;
	if (succ) {
		if (server->client[conn_fd]) {
			free(server->client[conn_fd]);
		}
		info->conn_fd = conn_fd;
		server->client[conn_fd] = info;
		header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
		header.res.client_id = info->conn_fd;
		char* homedir = get_user_homedir(server, info);
		mkdir(homedir, DIR_S_FLAG);
		free(homedir);
	} else {
		header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
		free(info);
	}
	send_message(conn_fd, &header, sizeof(header));
}

static void logout(csiebox_server* server, int conn_fd) {
	free(server->client[conn_fd]);
	server->client[conn_fd] = 0;
	close(conn_fd);
}

static void sync_file(csiebox_server* server, int conn_fd, csiebox_protocol_meta* meta, char *_path) {
	csiebox_client_info* info = server->client[conn_fd];
	char* homedir = get_user_homedir(server, info);
	printf("homedir = %s\n", homedir);
	char buf[PATH_MAX], req_path[PATH_MAX];
	memset(buf, 0, PATH_MAX);
	memset(req_path, 0, PATH_MAX);
	recv_message(conn_fd, buf, meta->message.body.pathlen);
	sprintf(req_path, "%s%s", homedir, buf);
	strcat(_path, buf);
	free(homedir);
	fprintf(stderr, "req_path: %s\n", req_path);
	struct stat stat;
	memset(&stat, 0, sizeof(struct stat));
	int need_data = 0, change = 0;
	if (lstat(req_path, &stat) < 0) {
		need_data = 1;
		change = 1;
	} else { 					
		if(stat.st_mode != meta->message.body.stat.st_mode) { 
			chmod(req_path, meta->message.body.stat.st_mode);
		}				
		if(stat.st_atime != meta->message.body.stat.st_atime ||
				stat.st_mtime != meta->message.body.stat.st_mtime){
			struct utimbuf* buf = (struct utimbuf*)malloc(sizeof(struct utimbuf));
			buf->actime = meta->message.body.stat.st_atime;
			buf->modtime = meta->message.body.stat.st_mtime;
			if(utime(req_path, buf)!=0){
				printf("time fail\n");
			}
		}
		uint8_t hash[MD5_DIGEST_LENGTH];
		memset(hash, 0, MD5_DIGEST_LENGTH);
		if ((stat.st_mode & S_IFMT) == S_IFDIR) {
		} else {
			md5_file(req_path, hash);
		}
		if (memcmp(hash, meta->message.body.hash, MD5_DIGEST_LENGTH) != 0) {
			need_data = 1;
		}
	}

	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	header.res.datalen = 0;
	header.res.client_id = conn_fd;
	if (need_data) {
		header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
	} else {
		header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	}
	send_message(conn_fd, &header, sizeof(header));

	if (need_data) {
		csiebox_protocol_file file;
		memset(&file, 0, sizeof(file));
		recv_message(conn_fd, &file, sizeof(file));
		fprintf(stderr, "sync file: %zd\n", file.message.body.datalen);
		if ((meta->message.body.stat.st_mode & S_IFMT) == S_IFDIR) {
			fprintf(stderr, "dir\n");
			mkdir(req_path, DIR_S_FLAG);
		} else {
			fprintf(stderr, "regular file\n");
			int fd = open(req_path, O_CREAT | O_WRONLY | O_TRUNC, REG_S_FLAG);
			size_t total = 0, readlen = 0;;
			char buf[4096];
			memset(buf, 0, 4096);
			while (file.message.body.datalen > total) {
				if (file.message.body.datalen - total < 4096) {
					readlen = file.message.body.datalen - total;
				} else {
					readlen = 4096;
				}
				if (!recv_message(conn_fd, buf, readlen)) {
					fprintf(stderr, "file broken\n");
					break;
				}
				total += readlen;
				if (fd > 0) {
					write(fd, buf, readlen);
				}
			}
			if (fd > 0) {
				close(fd);
			}
		}
		if (change) {
			chmod(req_path, meta->message.body.stat.st_mode);
			struct utimbuf* buf = (struct utimbuf*)malloc(sizeof(struct utimbuf));
			buf->actime = meta->message.body.stat.st_atime;
			buf->modtime = meta->message.body.stat.st_mtime;
			utime(req_path, buf);
		}
		header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
		header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
		send_message(conn_fd, &header, sizeof(header));
	}
}

static char* get_user_homedir(csiebox_server* server, csiebox_client_info* info) {
	char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
	memset(ret, 0, PATH_MAX);
	sprintf(ret, "%s/%s", server->arg.path, info->account.user);
	return ret;
}

static void rm_file(csiebox_server* server, int conn_fd, csiebox_protocol_rm* rm, char *_path) {
	csiebox_client_info* info = server->client[conn_fd];
	char* homedir = get_user_homedir(server, info);
	char req_path[PATH_MAX], buf[PATH_MAX];
	memset(req_path, 0, PATH_MAX);
	memset(buf, 0, PATH_MAX);
	recv_message(conn_fd, buf, rm->message.body.pathlen);
	sprintf(req_path, "%s%s", homedir, buf);
	strcat(_path, buf);
	free(homedir);
	fprintf(stderr, "rm (%zd, %s)\n", strlen(req_path), req_path);
	struct stat stat;
	memset(&stat, 0, sizeof(stat));
	lstat(req_path, &stat);
	if ((stat.st_mode & S_IFMT) == S_IFDIR) {
		rmdir(req_path);
	} else {
		unlink(req_path);
	}

	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_RM;
	header.res.datalen = 0;
	header.res.client_id = conn_fd;
	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	send_message(conn_fd, &header, sizeof(header));
}

// send msg for client to download the file at _path(relative path)
static void dl_file(int _conn_fd, char *_path) {
	// file stat and data
	struct stat file_info;
	char *file_data;
	// stat the file
	if(lstat(_path, &file_info) < 0) {
		fprintf(stderr, "Error: Stat %s\n", _path);
		exit(EXIT_FAILURE);
	}
	// get the file data if it is a reg file
	if( (file_info.st_mode & S_IFMT) == S_IFREG && file_info.st_size > 0 ) {
		int fdes = open(_path, O_RDONLY);
		if(fdes < 0) {
			fprintf(stderr, "Error: Open %s\n", _path);
			exit(EXIT_FAILURE);
		}
		file_data = (char *)mmap(NULL, file_info.st_size, PROT_READ, MAP_SHARED, fdes, 0);
		if(file_data == MAP_FAILED) {
			fprintf(stderr, "Error: Map %s\n", _path);
			exit(EXIT_FAILURE);
		}
	}
	// fill the protocol
	csiebox_protocol_meta req;
	memset( &req, 0, sizeof(req) );
	req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	req.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
	req.message.body.pathlen = strlen(_path) + 1;
	req.message.body.stat = file_info;
	// md5 the file data if it is a reg file
	if( (file_info.st_mode & S_IFMT) == S_IFREG && file_info.st_size > 0 )	md5(file_data, file_info.st_size, req.message.body.hash);
	// send msg to client
	if( !send_message( _conn_fd, &req, sizeof(req) ) ) {
		fprintf(stderr, "Error: Send Req\n");
		exit(EXIT_FAILURE);
	}
	if( !send_message(_conn_fd, _path, req.message.body.pathlen) ) {
		fprintf(stderr, "Error: Send Path\n");
		exit(EXIT_FAILURE);
	}
	// receive response
	csiebox_protocol_header header;
	memset( &header, 0, sizeof(header) );
	if( !recv_message( _conn_fd, &header, sizeof(header) ) ) {
		fprintf(stderr, "Error: Recv Response\n");
		exit(EXIT_FAILURE);
	}
	if(header.res.magic != CSIEBOX_PROTOCOL_MAGIC_RES || header.res.op != CSIEBOX_PROTOCOL_OP_SYNC_META) {
		fprintf(stderr, "Error: Response not match\n");
		exit(EXIT_FAILURE);
	}
	// status OK
	if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) {
		if( (file_info.st_mode & S_IFMT) == S_IFREG && file_info.st_size > 0 )	munmap(file_data, file_info.st_size);
		fprintf(stderr, "%s Meta Downloaded\n", _path);
		return;
	}
	if(header.res.status != CSIEBOX_PROTOCOL_STATUS_MORE)	return;
	// status more
	// fill the protocol
	csiebox_protocol_file reqF;
	memset( &reqF, 0, sizeof(reqF) );
	reqF.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	reqF.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
	reqF.message.header.req.datalen = sizeof(reqF) - sizeof(reqF.message.header);
	if( (file_info.st_mode & S_IFMT) == S_IFREG ) reqF.message.body.datalen = file_info.st_size;
	// send msg to client
	if( !send_message( _conn_fd, &reqF, sizeof(reqF) ) ) {
		fprintf(stderr, "Error: Send ReqF\n");
		exit(EXIT_FAILURE);
	}
	if(reqF.message.body.datalen > 0)
		if( !send_message(_conn_fd, file_data, reqF.message.body.datalen) ) {
			fprintf(stderr, "Error: Send File Data\n");
			exit(EXIT_FAILURE);
		}
	// receive response
	if( !recv_message( _conn_fd, &header, sizeof(header) ) ) {
		fprintf(stderr, "Error: Recv Response\n");
		exit(EXIT_FAILURE);
	}
	if(header.res.magic != CSIEBOX_PROTOCOL_MAGIC_RES || header.res.op != CSIEBOX_PROTOCOL_OP_SYNC_FILE) {
		fprintf(stderr, "Error: Response not match\n");
		exit(EXIT_FAILURE);
	}
	// status OK
	if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) fprintf(stderr, "%s File Downloaded\n", _path);
	else	exit(EXIT_FAILURE);
	// unmap the data
	if( (file_info.st_mode & S_IFMT) == S_IFREG && file_info.st_size > 0 )	munmap(file_data, file_info.st_size);
	return;
}

static void dl_rm(int _conn_fd, char *_path) {
	// fill the protocol
	csiebox_protocol_rm req;
	memset( &req, 0, sizeof(req) );
	req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	req.message.header.req.op = CSIEBOX_PROTOCOL_OP_RM;
	req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
	req.message.body.pathlen = strlen(_path) + 1;
	// send msg to client
	if( !send_message( _conn_fd, &req, sizeof(req) ) ) {
		fprintf(stderr, "Error: Send Req\n");
		exit(EXIT_FAILURE);
	}
	if( !send_message(_conn_fd, _path, req.message.body.pathlen) ) {
		fprintf(stderr, "Error: Send Path\n");
		exit(EXIT_FAILURE);
	}
	// receive response
	csiebox_protocol_header header;
	memset( &header, 0, sizeof(header) );
	if( !recv_message( _conn_fd, &header, sizeof(header) ) ) {
		fprintf(stderr, "Error: Recv Response\n");
		exit(EXIT_FAILURE);
	}
	if(header.res.magic != CSIEBOX_PROTOCOL_MAGIC_RES || header.res.op != CSIEBOX_PROTOCOL_OP_RM) {
		fprintf(stderr, "Error: Response not match\n");
		exit(EXIT_FAILURE);
	}
	// status OK
	if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK)	fprintf(stderr, "%s Rm Downloaded\n", _path);
	else	exit(EXIT_FAILURE);
	return;
}

static void start_traverse(csiebox_server *_server, int _conn_fd) {
	// current path
	char path[MAX_PATHLEN] = "./";
	// change dir to server home
	char *homedir = get_user_homedir(_server, _server->client[_conn_fd]);
	chdir(homedir);
	free(homedir);
	// start traverse
	if(traverse_dir(_server, _conn_fd, path) == -1)	exit(EXIT_FAILURE);
	// send sync end to client
	csiebox_protocol_header header;
	memset( &header, 0, sizeof(header) );
	header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_END;
	header.req.client_id = _conn_fd;
	send_message( _conn_fd, &header, sizeof(header) );
	return;
}

static int traverse_dir(csiebox_server *_server, int _conn_fd, char *_path) {
	// dirent and file stat
	struct dirent *d_ptr;
	struct stat file_info;
	// dir object for readdir
	DIR *dir = opendir(_path);
	// recognize current pathlen
	int pathlen = strlen(_path);
	// check entries in current dir
	while( ( d_ptr = readdir(dir) ) != NULL ) {
		// ignore "." and ".."
		if(strcmp(d_ptr->d_name, ".") == 0 || strcmp(d_ptr->d_name, "..") == 0)	continue;
		// updata current path
		_path[pathlen] = '\0';
		strcat(_path, d_ptr->d_name);
		//stat the specific file
		if(lstat(_path, &file_info) < 0) {
			fprintf(stderr, "Error: Stat %s\n", _path);
			return -1;
		}
		// add "/" at the end if this is a dir
		if( (file_info.st_mode & S_IFMT) == S_IFDIR ) strcat(_path, "/");
		// let the cliet download the file
		dl_file(_conn_fd, _path);
		// enter the next dir
		if( (file_info.st_mode & S_IFMT) == S_IFDIR ) {
			if(traverse_dir(_server, _conn_fd, _path) == -1)	return -1;
			dl_file(_conn_fd, _path);
		}
	}
	closedir(dir);
	_path[pathlen] = '\0';
	return 0;
}

