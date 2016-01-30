#include "csiebox_client.h"

#include "csiebox_common.h"
#include "connect.h"

#include "hash.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dirent.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <linux/inotify.h>

#define MAX_PATHLEN 400
#define MAX_HASH 100
#define EVENT_SIZE ( sizeof(struct inotify_event) )
#define EVENT_BUF_LEN ( 1024 * (EVENT_SIZE + 16) )

static int parse_arg(csiebox_client* client, int argc, char** argv);
static int login(csiebox_client* client);
static int start_traverse(csiebox_client *_client, int _noti_fd);
static int traverse_dir(csiebox_client *_client, char *_current_path, int _noti_fd, char *_longest_path);
static int get_depth(char *_path);
static int sync_meta_and_file(csiebox_client *_client, char *_path);
static int sync_rm(csiebox_client *_client, char *_path);
static int sync_hardlink(csiebox_client *_client, char *_path, int _flag_self_allowed);
static int find_same_file(ino_t _inode, char *_output, char *_current_path, char *_target_path);
static int add_watch_with_hash(csiebox_client *_client, char *_path, int _noti_fd);
static int start_listen(csiebox_client *_client, int _noti_fd);

//read config file, and connect to server
void csiebox_client_init(
  csiebox_client** client, int argc, char** argv) {
  csiebox_client* tmp = (csiebox_client*)malloc(sizeof(csiebox_client));
  if (!tmp) {
    fprintf(stderr, "client malloc fail\n");
    return;
  }
  memset(tmp, 0, sizeof(csiebox_client));
  if (!parse_arg(tmp, argc, argv)) {
    fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
    free(tmp);
    return;
  }
  int fd = client_start(tmp->arg.name, tmp->arg.server);
  if (fd < 0) {
    fprintf(stderr, "connect fail\n");
    free(tmp);
    return;
  }
  tmp->conn_fd = fd;
  *client = tmp;
}

//this is where client sends request, you sould write your code here
int csiebox_client_run(csiebox_client* client) {
  if (!login(client)) {
    fprintf(stderr, "login fail\n");
    return 0;
  }
  fprintf(stderr, "login success\n");
  
  if(init_hash(&(client->inotify_hash), MAX_HASH) == 0) {
	  fprintf(stderr, "Error: Init Hash\n");
	  return 0;
  }
  int noti_fd = inotify_init();
  if(noti_fd < 0) {
	  fprintf(stderr, "Error: Inotify Init\n");
	  return 0;
  }
  if(start_traverse(client, noti_fd) == -1) {
     fprintf(stderr, "Error: Traverse\n");
     return 0;
  }
  if(start_listen(client, noti_fd) == -1) {
  	  fprintf(stderr, "Error: Listen Dirs\n");
  	  return 0;
  }
  close(noti_fd);
  //====================
  //        TODO
  //====================
  
  
  return 1;
}

void csiebox_client_destroy(csiebox_client** client) {
  csiebox_client* tmp = *client;
  *client = 0;
  if (!tmp) {
    return;
  }
  close(tmp->conn_fd);
  free(tmp);
}

//read config file
static int parse_arg(csiebox_client* client, int argc, char** argv) {
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
  int accept_config_total = 5;
  int accept_config[5] = {0, 0, 0, 0, 0};
  while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
    key[keylen] = '\0';
    vallen = getline(&val, &valsize, file) - 1;
    val[vallen] = '\0';
    fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
    if (strcmp("name", key) == 0) {
      if (vallen <= sizeof(client->arg.name)) {
        strncpy(client->arg.name, val, vallen);
        accept_config[0] = 1;
      }
    } else if (strcmp("server", key) == 0) {
      if (vallen <= sizeof(client->arg.server)) {
        strncpy(client->arg.server, val, vallen);
        accept_config[1] = 1;
      }
    } else if (strcmp("user", key) == 0) {
      if (vallen <= sizeof(client->arg.user)) {
        strncpy(client->arg.user, val, vallen);
        accept_config[2] = 1;
      }
    } else if (strcmp("passwd", key) == 0) {
      if (vallen <= sizeof(client->arg.passwd)) {
        strncpy(client->arg.passwd, val, vallen);
        accept_config[3] = 1;
      }
    } else if (strcmp("path", key) == 0) {
      if (vallen <= sizeof(client->arg.path)) {
        strncpy(client->arg.path, val, vallen);
        accept_config[4] = 1;
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

static int login(csiebox_client* client) {
  csiebox_protocol_login req;
  memset(&req, 0, sizeof(req));
  req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  req.message.header.req.op = CSIEBOX_PROTOCOL_OP_LOGIN;
  req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
  memcpy(req.message.body.user, client->arg.user, strlen(client->arg.user));
  md5(client->arg.passwd,
      strlen(client->arg.passwd),
      req.message.body.passwd_hash);
  if (!send_message(client->conn_fd, &req, sizeof(req))) {
    fprintf(stderr, "send fail\n");
    return 0;
  }
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  if (recv_message(client->conn_fd, &header, sizeof(header))) {
    if (header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
        header.res.op == CSIEBOX_PROTOCOL_OP_LOGIN &&
        header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) {
      client->client_id = header.res.client_id;
      return 1;
    } else {
      return 0;
    }
  }
  return 0;
}

static int get_depth(char *_path) {
	int output = 0;
	while(*_path != '\0')	if(*_path++ == '/')	output++;
	return output;
}

static int traverse_dir(csiebox_client *_client, char *_current_path, int _noti_fd, char *_longest_path) {
	// dirent and file stat
	struct dirent *d_ptr;
	struct stat file_info;
	// dir object for readdir
	DIR *dir = opendir( _current_path );
	// add inotify_watcher
	if(add_watch_with_hash(_client, _current_path, _noti_fd) == -1) {
		fprintf(stderr, "Error: Add Watch On %s\n", _current_path);
		return -1;
	}
	// check the files and dirs in curent dir
	while( ( d_ptr = readdir(dir) ) != NULL ) {
		// ignore "." and ".."
		if(strcmp(d_ptr->d_name, ".") == 0 || strcmp(d_ptr->d_name, "..") == 0)	continue;
		// new current path
		char current_path[MAX_PATHLEN];
		strcpy(current_path, _current_path);
		strcat(current_path, d_ptr->d_name);
		// updata the longest_path
		if( get_depth(current_path) > get_depth(_longest_path) )	strcpy(_longest_path, current_path);
		// stat the specific file
		if(lstat(current_path, &file_info) < 0) {
			fprintf(stderr, "Error: Stat %s\n", current_path);
			return -1;
		}
		// add "/" at the end if this is a dir
		if( (file_info.st_mode & S_IFMT) == S_IFDIR )	strcat(current_path, "/");
		// sync hardlink
		if( (file_info.st_mode & S_IFMT) == S_IFREG && file_info.st_nlink > 1 ) {
			if(sync_hardlink(_client, current_path, 1) == -1) {
				fprintf(stderr, "Error: Sync Hard Link %s\n", current_path);
				return -1;
			}
		}
		// sync meta and file
		else {
			if(sync_meta_and_file(_client, current_path) == -1) {
				fprintf(stderr, "Error: Sync %s\n", current_path);
				return -1;
			}
		}
		// reg file or hard link
		if( (file_info.st_mode & S_IFMT) == S_IFREG ) {
			if(file_info.st_nlink <= 1)	printf("<System> Regular File %s Completed\n", current_path);
			else	printf("<System> Hard Link %s Completed\n", current_path);
		}
		// soft link
		else if( (file_info.st_mode & S_IFMT) == S_IFLNK )	printf("<System> Symbolic Link %s Completed\n", current_path);
		// dir
		else if( (file_info.st_mode & S_IFMT) == S_IFDIR ) {
			printf("<System> Enter Dir: %s\n", current_path);
			if(traverse_dir(_client, current_path, _noti_fd, _longest_path) == -1)	return -1;
			printf("<System> Leave Dir: %s\n", current_path);
			// sync again to make the ctime syncked
			if(sync_meta_and_file(_client, current_path) == -1) {
				fprintf(stderr, "Error: Sync %s\n", current_path);
				return -1;
			}
		}
	}
	closedir(dir);
	return 0;
}

static int start_traverse(csiebox_client *_client, int _noti_fd) {
	// current_path
	char current_path[MAX_PATHLEN] = "./";
	// longest_path
	char longest_path[MAX_PATHLEN] = "./";
	// go to the work space of the specific user
	chdir(_client->arg.path);
	// traverse from the root(work space)
	if(traverse_dir(_client, current_path, _noti_fd, longest_path) == -1)	return -1;
	// write the res of longest path into file(ignore "./")
	FILE *fp = fopen("longestPath.txt", "w");
	if(fp == NULL) {
		fprintf(stderr, "Error: Open longestPath.txt\n");
		return -1;
	}
	fprintf(fp, "%s", longest_path + 2);
	fclose(fp);
	return 0;
}

static int sync_meta_and_file(csiebox_client *_client, char *_path) {
	// file stat , file data and link data(for soft link)
	struct stat file_info;
	char *file_data;
	char link_path[MAX_PATHLEN];
	// stat the specific file
	if(lstat(_path, &file_info) < 0) {
		fprintf(stderr, "Error: Stat %s\n", _path);
		return -1;
	}
	// open the file and map it on memory if it is a reg file
	if( (file_info.st_mode & S_IFMT) == S_IFREG && file_info.st_size > 0 ) {
		int fdes = open(_path, O_RDONLY);
		if(fdes < 0) {
			fprintf(stderr, "Error: Open %s\n", _path);
			return -1;
		}
		file_data = (char *)mmap(NULL, file_info.st_size, PROT_READ, MAP_SHARED, fdes, 0);
		if(file_data == MAP_FAILED) {
			fprintf(stderr, "Error: Map %s\n", _path);
			return -1;
		}
		close(fdes);
	}
	// if it is a soft link
	else if( (file_info.st_mode & S_IFMT) == S_IFLNK ) {
		int length = readlink(_path, link_path, MAX_PATHLEN);
		if(length < 0) {
			fprintf(stderr, "Error: Read Soft Link %s\n", _path);
			return -1;
		}
		link_path[length] = '\0'; 
		file_data = link_path;
	}
	// send protocol to server
	csiebox_protocol_meta req;
	memset( &req, 0, sizeof(req) );
	req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	req.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
	req.message.body.pathlen = strlen(_path) + 1;
	req.message.body.stat = file_info;
	if( ( (file_info.st_mode & S_IFMT) == S_IFREG && file_info.st_size > 0 ) || (file_info.st_mode & S_IFMT) == S_IFLNK )
		md5(file_data, strlen(file_data), req.message.body.hash);
	if( !send_message( _client->conn_fd, &req, sizeof(req) ) ) {
		fprintf(stderr, "send fail\n");
		return -1;
	}
	//send full path to server
	if( !send_message(_client->conn_fd, _path, req.message.body.pathlen) ) {
		fprintf(stderr, "send fail\n");
		return -1;
	}
	// receive the response
	csiebox_protocol_header header;
	memset( &header, 0, sizeof(header) );
	if( recv_message( _client->conn_fd, &header, sizeof(header) ) ) {
		if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES && header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_META) {
			if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) {
				if( (file_info.st_mode & S_IFMT) == S_IFREG && file_info.st_size > 0)
					munmap(file_data, file_info.st_size);
				printf("%s Sync Meta Succeed\n", _path);
				return 0;
			}
			else if(header.res.status == CSIEBOX_PROTOCOL_STATUS_MORE)	printf("%s Need File Data\n", _path);
			else	return -1;
		}
		else	return -1;
	}
	else	return -1;
	// need to sync data
	csiebox_protocol_file reqF;
	memset( &reqF, 0, sizeof(reqF) );
	reqF.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	reqF.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
	reqF.message.header.req.datalen = sizeof(reqF) - sizeof(reqF.message.header);
	// datalen = st_size if it is a reg file
	if( (file_info.st_mode & S_IFMT) == S_IFREG )	reqF.message.body.datalen = file_info.st_size;
	// datalen = strlen of file_data + 1 if it is a softlink
	else if( (file_info.st_mode & S_IFMT) == S_IFLNK )	reqF.message.body.datalen = strlen(file_data) + 1;
	// send sync file msg to server
	if( !send_message( _client->conn_fd, &reqF, sizeof(reqF) ) ) {
		fprintf(stderr, "send fail\n");
		return -1;
	}
	// send full file data
	if(reqF.message.body.datalen > 0) {
		if( !send_message(_client->conn_fd, file_data, reqF.message.body.datalen) ) {
			fprintf(stderr, "send fail\n");
			return -1;
		}
	}
	// get the response
	if( recv_message( _client->conn_fd, &header, sizeof(header) ) ) {
		if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES && header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_FILE) {
			if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK)	printf("%s Sync File Succeed\n", _path);
			else	return -1;
		}
		else	return -1;
	}
	else	return -1;
	// unmap the memory
	if( (file_info.st_mode & S_IFMT) == S_IFREG && file_info.st_size > 0)	munmap(file_data, file_info.st_size);
	return 0;
}

static int sync_rm(csiebox_client *_client, char *_path) {
	// fill the protocol object
	csiebox_protocol_rm req;
	memset( &req, 0, sizeof(req) );
	req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	req.message.header.req.op = CSIEBOX_PROTOCOL_OP_RM;
	req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
	req.message.body.pathlen = strlen(_path) + 1;
	// sent rm protocol to server
	if( !send_message( _client->conn_fd, &req, sizeof(req) ) ) {
		fprintf(stderr, "send fail\n");
		return -1;
	}
	//send full path to server
	if( !send_message(_client->conn_fd, _path, req.message.body.pathlen) ) {
		fprintf(stderr, "send fail\n");
		return -1;
	}
	// receive the response
	csiebox_protocol_header header;
	memset( &header, 0, sizeof(header) );
	if( recv_message( _client->conn_fd, &header, sizeof(header) ) ) {
		if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES && header.res.op == CSIEBOX_PROTOCOL_OP_RM) {
			if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) printf("%s Sync Remove Succeed\n", _path);
			else	return -1;
		}
		else	return -1;
	}
	else	return -1;
	return 0;
}

static int sync_hardlink(csiebox_client *_client, char *_path, int _flag_self_allowed) {
	// file stat and src path
	struct stat file_info;
	char srcpath[MAX_PATHLEN];
	// stat the specific file
	if(lstat(_path, &file_info) < 0) {
		fprintf(stderr, "Error: Stat %s\n", _path);
		return -1;
	}
	// get the inod num
	ino_t inode = file_info.st_ino;
	// find the src path
	char *tmp_target_path = NULL;
	if(!_flag_self_allowed)	tmp_target_path = _path;
	if(find_same_file(inode, srcpath, "./", tmp_target_path) == -1 || strcmp(srcpath, _path) == 0)
		return sync_meta_and_file(_client, _path);
	// fill the protocol object
	csiebox_protocol_hardlink req;
	memset( &req, 0, sizeof(req) );
	req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	req.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK;
	req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
	req.message.body.srclen = strlen(srcpath) + 1;
	req.message.body.targetlen = strlen(_path) + 1;
	// sent hardlink protocol to server
	if( !send_message( _client->conn_fd, &req, sizeof(req) ) ) {
		fprintf(stderr, "send fail\n");
		return -1;
	}
	//send full srcpath to server
	if( !send_message(_client->conn_fd, srcpath, req.message.body.srclen) ) {
		fprintf(stderr, "send fail\n");
		return -1;
	}
	//send full targetpath to server
	if( !send_message(_client->conn_fd, _path, req.message.body.targetlen) ) {
		fprintf(stderr, "send fail\n");
		return -1;
	}
	// receive the response
	csiebox_protocol_header header;
	memset( &header, 0, sizeof(header) );
	if( recv_message( _client->conn_fd, &header, sizeof(header) ) ) {
		if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES && header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK) {
			if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) printf("%s Sync Hard Link Succeed\n", _path);
			else	return -1;
		}
		else	return -1;
	}
	else	return -1;
	// stnc file again to make ctime syncked
	return sync_meta_and_file(_client, _path);
}

static int find_same_file(ino_t _inode, char *_output, char *_current_path, char *_target_path) { 
	// dirent and file stat
	struct dirent *d_ptr;
	struct stat file_info;
	// dir object for readdir
	DIR *dir = opendir( _current_path );
	// check the files and dirs in curent dir
	while( ( d_ptr = readdir(dir) ) != NULL ) {
		// ignore "." and ".."
		if(strcmp(d_ptr->d_name, ".") == 0 || strcmp(d_ptr->d_name, "..") == 0)	continue;
		// new current path
		char current_path[MAX_PATHLEN];
		strcpy(current_path, _current_path);
		strcat(current_path, d_ptr->d_name);
		// stat the specific file
		if(lstat(current_path, &file_info) < 0) {
			fprintf(stderr, "Error: Stat %s\n", current_path);
			return -1;
		}
		// add "/" at the end if this is a dir
		if( (file_info.st_mode & S_IFMT) == S_IFDIR )	strcat(current_path, "/");
		// reg file
		if( (file_info.st_mode & S_IFMT) == S_IFREG && file_info.st_ino == _inode ) {
			if(_target_path == NULL || strcmp(current_path, _target_path) != 0) {
				printf("%s is the Source of Hard Link\n", current_path);
				strcpy(_output, current_path);
				closedir(dir);
				return 0;
			}
		}
		// dir
		else if( (file_info.st_mode & S_IFMT) == S_IFDIR ) {
			if(find_same_file(_inode, _output, current_path, _target_path) == 0) {
				closedir(dir);
				return 0;
			}
		}
	}
	closedir(dir);
	return -1;
}

static int add_watch_with_hash(csiebox_client *_client, char *_path, int _noti_fd) {
	int wd = inotify_add_watch(_noti_fd, _path, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY | IN_MOVE);
	char *path_to_hash = (char *)malloc(sizeof(char) * MAX_PATHLEN);
	strcpy(path_to_hash, _path);
	if(put_into_hash(&(_client->inotify_hash), (void *)path_to_hash, wd) == 0) {
		fprintf(stderr, "Error: Hash %s\n", path_to_hash);
		return -1;
	}
	return 0;
}

static int start_listen(csiebox_client *_client, int _noti_fd) {
	// length for read's return value and buffer for read
	int length = 0;
	char buffer[EVENT_BUF_LEN];
	while( (length = read(_noti_fd, buffer, EVENT_BUF_LEN) ) > 0 ) {
		int i = 0;
		while(i < length) {
			// check the i th event
			struct inotify_event* event = (struct inotify_event*)&buffer[i];
			char *path_tmp, path[MAX_PATHLEN];
			printf("Event Got: (%d, %d, %s)\n", event->wd, strlen(event->name), event->name);
			// get the full file path
			if(get_from_hash(&(_client->inotify_hash), (void **)&path_tmp, event->wd) == 0) {
				fprintf(stderr, "Error: UnHash %s\n", path_tmp);
				return -1;
			}
			strcpy(path, path_tmp);
			strcat(path, event->name);
			if(event->mask & IN_ISDIR) {
				if(event->mask & IN_CREATE) {
					strcat(path, "/");
					if(add_watch_with_hash(_client, path, _noti_fd) == -1) {
						fprintf(stderr, "Error: Add Watch On %s\n", path);
						return -1;
					}
				}
				else if(event->mask & IN_DELETE_SELF) {
					if(del_from_hash(&(_client->inotify_hash), (void **)&path_tmp, event->wd) == 0) {
						fprintf(stderr, "Error: UnHash %s\n", path_tmp);
						free(path_tmp);
						return -1;
					}
				}
			}
			// if create or moved to
			if( (event->mask & IN_CREATE) || (event->mask & IN_MOVED_TO) ) {
				printf("<System> Creating %s on Server...\n", path);
				// stat the specific file
				struct stat file_info;
				if(lstat(path, &file_info) < 0) {
					fprintf(stderr, "Error: Stat %s\n", path);
					return -1;
				}
				// sync hardlink
				if( (file_info.st_mode & S_IFMT) == S_IFREG && file_info.st_nlink > 1 ) {
					if(sync_hardlink(_client, path, 0) == -1) {
						fprintf(stderr, "Error: Sync Hard Link %s\n", path);
						return -1;
					}
				}
				// sync meta and file
				else {
					if(sync_meta_and_file(_client, path) == -1) {
						fprintf(stderr, "Error: Sync %s\n", path);
						return -1;
					}
				}
			}
			// if delete or moved from
			if( (event->mask & IN_DELETE) || (event->mask & IN_MOVED_FROM) ) {
				printf("<System> Removing %s on Server...\n", path);
				if(sync_rm(_client, path) == -1) {
					fprintf(stderr, "Error: Syne %s in Remove\n", path);
				}
			}
			// if attrib and modified
			if( (event->mask & IN_ATTRIB) || (event->mask & IN_MODIFY) ) {
				printf("<Sysyem> Syncking %s on Server...\n", path);
				if(sync_meta_and_file(_client, path) == -1) {
					fprintf(stderr, "Error: Sync %s in ATTRIB\n", path);
					return -1;
				}
			}
			i += (EVENT_SIZE + event->len);
		}
		memset(buffer, 0, EVENT_BUF_LEN);
	}
	return 0;
}
