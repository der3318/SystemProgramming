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
#include <sys/mman.h>
#include <dirent.h>
#include <unistd.h>
#include <libgen.h>
#include <fcntl.h>
#include <utime.h>

static int parse_arg(csiebox_server* server, int argc, char** argv);
static void handle_request(csiebox_server* server, int conn_fd);
static int get_account_info(
  csiebox_server* server,  const char* user, csiebox_account_info* info);
static void login(
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void logout(csiebox_server* server, int conn_fd);
static char* get_user_homedir(
  csiebox_server* server, csiebox_client_info* info);
static void sync_meta_and_file(csiebox_server *_server, int _conn_fd, csiebox_protocol_meta *_meta);
static void sync_rm(csiebox_server *_server, int _conn_fd, csiebox_protocol_rm *_rm);
static void sync_hardlink(csiebox_server *_server, int _conn_fd, csiebox_protocol_hardlink *_hardlink);

#define DIR_S_FLAG (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)//permission you can use to create new file
#define REG_S_FLAG (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)//permission you can use to create new directory

//read config file, and start to listen
void csiebox_server_init(
  csiebox_server** server, int argc, char** argv) {
  csiebox_server* tmp = (csiebox_server*)malloc(sizeof(csiebox_server));
  if (!tmp) {
    fprintf(stderr, "server malloc fail\n");
    return;
  }
  memset(tmp, 0, sizeof(csiebox_server));
  if (!parse_arg(tmp, argc, argv)) {
    fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
    free(tmp);
    return;
  }
  int fd = server_start();
  if (fd < 0) {
    fprintf(stderr, "server fail\n");
    free(tmp);
    return;
  }
  tmp->client = (csiebox_client_info**)
      malloc(sizeof(csiebox_client_info*) * getdtablesize());
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

//wait client to connect and handle requests from connected socket fd
int csiebox_server_run(csiebox_server* server) {
  int conn_fd, conn_len;
  struct sockaddr_in addr;
  while (1) {
    memset(&addr, 0, sizeof(addr));
    conn_len = 0;
    // waiting client connect
    conn_fd = accept(
      server->listen_fd, (struct sockaddr*)&addr, (socklen_t*)&conn_len);
    if (conn_fd < 0) {
      if (errno == ENFILE) {
          fprintf(stderr, "out of file descriptor table\n");
          continue;
        } else if (errno == EAGAIN || errno == EINTR) {
          continue;
        } else {
          fprintf(stderr, "accept err\n");
          fprintf(stderr, "code: %s\n", strerror(errno));
          break;
        }
    }
    // handle request from connected socket fd
    handle_request(server, conn_fd);
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
  int i = getdtablesize() - 1;
  for (; i >= 0; --i) {
    if (tmp->client[i]) {
      free(tmp->client[i]);
    }
  }
  free(tmp->client);
  free(tmp);
}

//read config file
static int parse_arg(csiebox_server* server, int argc, char** argv) {
  if (argc != 2) {
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
    fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
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

//this is where the server handle requests, you should write your code here
static void handle_request(csiebox_server* server, int conn_fd) {
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  while (recv_message(conn_fd, &header, sizeof(header))) {
    if (header.req.magic != CSIEBOX_PROTOCOL_MAGIC_REQ) {
      continue;
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
        fprintf(stderr, "sync meta and file\n");
        csiebox_protocol_meta meta;
        if (complete_message_with_header(conn_fd, &header, &meta)) {
          sync_meta_and_file(server, conn_fd, &meta);
          //====================
          //        TODO
          //====================
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_FILE:
        fprintf(stderr, "sync file\n");
        csiebox_protocol_file file;
        if (complete_message_with_header(conn_fd, &header, &file)) {
          //====================
          //        TODO
          //====================
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK:
        fprintf(stderr, "sync hardlink\n");
        csiebox_protocol_hardlink hardlink;
        if (complete_message_with_header(conn_fd, &header, &hardlink)) {
          sync_hardlink(server, conn_fd, &hardlink);
          //====================
          //        TODO
          //====================
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_END:
        fprintf(stderr, "sync end\n");
        csiebox_protocol_header end;
          //====================
          //        TODO
          //====================
        break;
      case CSIEBOX_PROTOCOL_OP_RM:
        fprintf(stderr, "rm\n");
        csiebox_protocol_rm rm;
        if (complete_message_with_header(conn_fd, &header, &rm)) {
          sync_rm(server, conn_fd, &rm);
          //====================
          //        TODO
          //====================
        }
        break;
      default:
        fprintf(stderr, "unknown op %x\n", header.req.op);
        break;
    }
  }
  fprintf(stderr, "end of connection\n");
  logout(server, conn_fd);
}

//open account file to get account information
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
      fprintf(stderr, "illegal form in account file, line %d\n", line);
      continue;
    }
    if (strcmp(user, u) == 0) {
      memcpy(info->user, user, strlen(user));
      char* passwd = strtok(NULL, ",");
      if (!passwd) {
        fprintf(stderr, "illegal form in account file, line %d\n", line);
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

//handle the login request from client
static void login(
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login) {
  int succ = 1;
  csiebox_client_info* info =
    (csiebox_client_info*)malloc(sizeof(csiebox_client_info));
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

static char* get_user_homedir(
  csiebox_server* server, csiebox_client_info* info) {
  char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
  memset(ret, 0, PATH_MAX);
  sprintf(ret, "%s/%s", server->arg.path, info->account.user);
  return ret;
}

static void sync_meta_and_file(csiebox_server *_server, int _conn_fd, csiebox_protocol_meta *_meta) {
	// retrieve data from meta protocol
	int pathlen = _meta->message.body.pathlen;
	struct stat file_info = _meta->message.body.stat;
	// allocate memory for filepath
	char path[pathlen];
	// flag for MORE
	int flag_more = 0;
	// create response header
	csiebox_protocol_header header;
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	header.res.datalen = 0;
	header.res.client_id = _conn_fd;
	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	// get the full path via socket
	if( recv_message(_conn_fd, path, pathlen) ) {
		// change dir to the user's homedir on server
		chdir( get_user_homedir(_server, _server->client[_conn_fd]) );
		// dir
		if( (file_info.st_mode & S_IFMT) == S_IFDIR ) {
			// create dir and sync meta
			mkdir(path, file_info.st_mode);
			struct utimbuf times = {.actime =  file_info.st_atime, .modtime = file_info.st_mtime};
			utime(path, &times);
			chmod(path, file_info.st_mode);
			chown(path, file_info.st_uid, file_info.st_gid);
		}
		// reg file
		else if( (file_info.st_mode & S_IFMT) == S_IFREG ) {
			// create one if the file doesn't exit
			FILE *fp = fopen(path, "r+");
			if(fp == NULL)	fp = fopen(path, "w");
			// sync meta
			struct utimbuf times = {.actime =  file_info.st_atime, .modtime = file_info.st_mtime};
			utime(path, &times);
			chmod(path, file_info.st_mode);
			chown(path, file_info.st_uid, file_info.st_gid);
			fclose(fp);
		}
		// soft link
		else if( (file_info.st_mode & S_IFMT) == S_IFLNK ) {
			// remove old and create a new one
			unlink(path);
			if(symlink(path, path) < 0)	fprintf(stderr, "Error: Create Soft Link %s\n", path);
		}
		// hash the file on serve
		struct stat file_info_self;
		uint8_t hash[MD5_DIGEST_LENGTH];
		memset(hash, 0, MD5_DIGEST_LENGTH);
		if(lstat(path, &file_info_self) < 0)	fprintf(stderr, "Error: Stat %s\n", path);
		// reg file
		if( (file_info_self.st_mode & S_IFMT) == S_IFREG && file_info_self.st_size > 0 ) {
			int fdes = open(path, O_RDONLY);
			char *file_data;
			if(fdes < 0)	fprintf(stderr, "Error: Open %s\n", path);
			file_data = (char *)mmap(NULL, file_info_self.st_size, PROT_READ, MAP_SHARED, fdes, 0);
			if(file_data == MAP_FAILED)	fprintf(stderr, "Error: Map %s\n", path);
			md5(file_data, strlen(file_data), hash);
			munmap(file_data, file_info_self.st_size);
			close(fdes);
		}
		// check hash
      	if(memcmp(_meta->message.body.hash, hash, MD5_DIGEST_LENGTH) != 0) {
			header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
			flag_more = 1;
		}
	}
	else	header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
	// send message back to the user
	if( !send_message( _conn_fd, &header, sizeof(header) ) )	fprintf(stderr, "Error: Sent Msg\n");
	if(flag_more == 0)	return;
	// receive the datalen
	memset( &header, 0, sizeof(header) );
	if( !recv_message( _conn_fd, &header, sizeof(header) ) )	fprintf(stderr, "Receive File Pro Error\n");
	csiebox_protocol_file file;
    if( !complete_message_with_header(_conn_fd, &header, &file) )	fprintf(stderr, "Complete Msg Error\n");
	int datalen = file.message.body.datalen;
	// receive the file data
	char *data = (char *)malloc(sizeof(char) * datalen);
	if( datalen != 0 && !recv_message( _conn_fd, data, datalen ) )	fprintf(stderr, "Receive File Data Error\n");
	// write data into reg file
	if( (file_info.st_mode & S_IFMT) == S_IFREG) {
		FILE *fp_w = fopen(path, "w");
		if(fp_w == NULL)	fprintf(stderr, "Error: Write %s\n", path);
		fwrite(data, sizeof(char), datalen, fp_w);
		struct utimbuf times = {.actime =  file_info.st_atime, .modtime = file_info.st_mtime};
		utime(path, &times);
		fclose(fp_w);
	}
	// write target into soft link
	else if( (file_info.st_mode & S_IFMT) == S_IFLNK ) {
		// remove old and create a new one
		unlink(path);
		if(symlink(data, path) < 0)	fprintf(stderr, "Error: Create Soft Link %s\n", path);
	}
	free(data);
	// send message bakck to the user
	memset( &header, 0, sizeof(header) );
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	header.res.datalen = 0;
	header.res.client_id = _conn_fd;
	if( !send_message( _conn_fd, &header, sizeof(header) ) )	fprintf(stderr, "Error: Sent Msg\n");
}

static void sync_rm(csiebox_server *_server, int _conn_fd, csiebox_protocol_rm *_rm) {
	// retrieve data from rm protocol
	int pathlen = _rm->message.body.pathlen;
	// allocate memory for filepath
	char path[pathlen];
	// create response header
	csiebox_protocol_header header;
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_RM;
	header.res.datalen = 0;
	header.res.client_id = _conn_fd;
	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	// get the full path via socket
	if( !recv_message(_conn_fd, path, pathlen) ) {
		fprintf(stderr, "Error: Receive RM Msg\n");
		header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
	}
	// change the dir to the homedir
	chdir( get_user_homedir(_server, _server->client[_conn_fd]) );
	// stat the file
	struct stat file_info;
	if(lstat(path, &file_info) < 0) {
		fprintf(stderr, "Error: Stat %s\n", path);
		header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
	}
	// dir
	if( (file_info.st_mode & S_IFMT) == S_IFDIR )	rmdir(path);
	else	unlink(path);
	if( !send_message( _conn_fd, &header, sizeof(header) ) )	fprintf(stderr, "Error: Sent Msg\n");
}

static void sync_hardlink(csiebox_server *_server, int _conn_fd, csiebox_protocol_hardlink *_hardlink) {
	// retrieve data from hardlink protocol
	int srclen = _hardlink->message.body.srclen;
	int targetlen = _hardlink->message.body.targetlen;
	// allocate memory for path
	char srcpath[srclen];
	char targetpath[targetlen];
	// create response header
	csiebox_protocol_header header;
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK;
	header.res.datalen = 0;
	header.res.client_id = _conn_fd;
	header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	// get the full path via socket
	if( !recv_message(_conn_fd, srcpath, srclen) ) {
		fprintf(stderr, "Error: Receive Hard Link Msg\n");
		header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
	}
	if( !recv_message(_conn_fd, targetpath, targetlen) ) {
		fprintf(stderr, "Error: Receive Hard Link Msg\n");
		header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
	}
	// change the dir to the homedir
	chdir( get_user_homedir(_server, _server->client[_conn_fd]) );
	// open the src file, it not exist, create one
	FILE *fp = fopen(srcpath, "r+");
	if(fp == NULL)	fp = fopen(srcpath, "w");
	fclose(fp);
	if(link(srcpath, targetpath) < 0) {
		fprintf(stderr, "Error: Hard Link from %s to %s\n", targetpath, srcpath);
		header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
	}
	if( !send_message( _conn_fd, &header, sizeof(header) ) )	fprintf(stderr, "Error: Sent Msg\n");
}
