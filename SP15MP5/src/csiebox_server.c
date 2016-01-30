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

#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

static int parse_arg(csiebox_server* server, int argc, char** argv);
static int clean_request(csiebox_server* server, int conn_fd);
static int handle_request(csiebox_server* server, int conn_fd);
static int get_account_info(csiebox_server* server,  const char* user, csiebox_account_info* info);
static void login(csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void logout(csiebox_server* server, int conn_fd);
static void sync_file(csiebox_server* server, int conn_fd, csiebox_protocol_meta* meta);
static char* get_user_homedir(csiebox_server* server, csiebox_client_info* info);
static void rm_file(csiebox_server* server, int conn_fd, csiebox_protocol_rm* rm);
static void handle_user1(int _signal, siginfo_t *_info, void *_context);
static void handle_term(int _signal, siginfo_t *_info, void *_context);
static void handle_int(int _signal, siginfo_t *_info, void *_context);
static void daemonize(csiebox_server *_server);

TaskData **data;
int nthread;
char *fifo_path;

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

// global fd set
fd_set master;
// global lock for the set
pthread_mutex_t master_mutex;

void *threadTask(void *arg) {
	while(1) {
		// get the arg
		TaskData *data = (TaskData *)arg;
		csiebox_server *server = data->server;
		// it is not working
		if(data->conn_fd == 0)	continue;
		if(handle_request(server, data->conn_fd) != -1) {
			// did not logout, so put the fd back to the set
			pthread_mutex_lock(&master_mutex);
			FD_SET(data->conn_fd, &master);
			pthread_mutex_unlock(&master_mutex);
		}
		// back to the status that denotes not working
		pthread_mutex_lock( &(data->mutex) );
		data->conn_fd = 0;
		pthread_mutex_unlock( &(data->mutex) );
	}
	pthread_exit(NULL);
}

int csiebox_server_run(csiebox_server* server) {
	if(server->arg.isDaemon == 1)	daemonize(server);
	// create fifo
	fifo_path = (char *)malloc(sizeof(char) * PATH_MAX);
	memset(fifo_path, 0, sizeof(char) * PATH_MAX);
	strcpy(fifo_path, server->arg.run_path);
	if(fifo_path[strlen(fifo_path) - 1] == '/')	strcat(fifo_path, "fifo.");
	else	strcat(fifo_path, "/fifo.");
	sprintf( fifo_path + strlen(fifo_path), "%ld", (long)getpid() );
	mkfifo(fifo_path, 0666);
	// set sigaction
	struct sigaction act_user1, act_term, act_int;
	memset( &act_user1, 0, sizeof(act_user1) );
	memset( &act_term, 0, sizeof(act_term) );
	memset( &act_int, 0, sizeof(act_int) );
	act_user1.sa_sigaction = &handle_user1;
	act_user1.sa_flags = SA_SIGINFO | SA_RESTART;
	act_term.sa_sigaction = &handle_term;
	act_term.sa_flags = SA_SIGINFO;
	act_int.sa_sigaction = &handle_int;
	act_int.sa_flags = SA_SIGINFO;
	if(sigaction(SIGUSR1, &act_user1, NULL) < 0) {
		fprintf(stderr, "Error: Create SigAction\n");
		exit(-1);
	}
	if(sigaction(SIGTERM, &act_term, NULL) < 0) {
		fprintf(stderr, "Error: Create SigAction\n");
		exit(-1);
	}
	if(sigaction(SIGINT, &act_int, NULL) < 0) {
		fprintf(stderr, "Error: Create SigAction\n");
		exit(-1);
	}
	// create threads to do the tasks
	pthread_t threads[server->arg.nthread];
	// init the lock for master set
	pthread_mutex_init(&master_mutex, NULL);
	// init the data structures used to communicate with threads and the number of threads
	nthread = server->arg.nthread;
	data = (TaskData **)malloc(sizeof(TaskData *) * server->arg.nthread);
	for(int i = 0 ; i < server->arg.nthread ; i++) {
		data[i] = (TaskData *)malloc( sizeof(TaskData) );
		data[i]->server = server;
		data[i]->conn_fd = 0;
		pthread_mutex_init(&(data[i]->mutex), NULL);
		if( pthread_create( &threads[i], NULL, threadTask, (void *)data[i] ) ) {
			fprintf(stderr, "Error: Create Thread\n");
			exit(-1);
		}
	}
	// max fd to trace
	int fdmax = server->listen_fd;
	// setup tmp fd set
	fd_set read_fds;
	// setup master set
	pthread_mutex_lock(&master_mutex);
	FD_SET(server->listen_fd, &master);
	pthread_mutex_unlock(&master_mutex);
	int conn_fd, conn_len;
	struct sockaddr_in addr;
	memset( &addr, 0, sizeof(addr) );
	conn_len = sizeof(addr);
	while (1) {
		// copy master into read_fds
		read_fds = master;
		// select the valid fds
		struct timeval timeout = {.tv_sec = 0, .tv_usec = 10000};
		if(select(fdmax + 1, &read_fds, NULL, NULL, &timeout) == -1)	continue;
		for(int fdnow = 0 ; fdnow <= fdmax ; fdnow++) {
			// new connection
			if(FD_ISSET(fdnow, &read_fds) && fdnow == server->listen_fd) {
				conn_fd = accept(server->listen_fd, (struct sockaddr*)&addr, (socklen_t*)&conn_len);
				if(conn_fd < 0) {
					fprintf( stderr, "Error: Accept with errno: %s\n", strerror(errno) );
					exit(EXIT_FAILURE);
				}
				pthread_mutex_lock(&master_mutex);
				FD_SET(conn_fd, &master);
				pthread_mutex_unlock(&master_mutex);
				if(conn_fd > fdmax)	fdmax = conn_fd;
			}
			// tell a thread to handle the request of connected client
			else if( FD_ISSET(fdnow, &read_fds) ) {
				int i = 0;
				// find an available thread
				for(i = 0 ; i < server->arg.nthread ; i++)
					if(data[i]->conn_fd == 0) {
						pthread_mutex_lock(&master_mutex);
						FD_CLR(fdnow, &master);
						pthread_mutex_unlock(&master_mutex);
						pthread_mutex_lock( &(data[i]->mutex) );
						data[i]->conn_fd = fdnow;
						pthread_mutex_unlock( &(data[i]->mutex) );
						break;
					}
				// no thread is available now
				if(i == server->arg.nthread) {
					csiebox_protocol_header header;
					memset( &header, 0, sizeof(header) );
					header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
					header.res.op = CSIEBOX_PROTOCOL_OP_LOGIN;
					header.res.datalen = 0;
					header.res.client_id = fdnow;
					header.res.status = CSIEBOX_PROTOCOL_STATUS_BUSY;
					send_message( fdnow, &header, sizeof(header) );
					// clean the msg
					if(clean_request(server, fdnow) == -1) {
						pthread_mutex_lock(&master_mutex);
						FD_CLR(fdnow, &master);
						pthread_mutex_unlock(&master_mutex);
					}
				}
			}
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
	// handle daemon
	if(argc == 3)
		if(strcmp(argv[2], "-d") == 0)	server->arg.isDaemon = 1;
	FILE* file = fopen(argv[1], "r");
	if (!file) {
		return 0;
	}
	fprintf(stderr, "reading config...\n");
	size_t keysize = 20, valsize = 20;
	char* key = (char*)malloc(sizeof(char) * keysize);
	char* val = (char*)malloc(sizeof(char) * valsize);
	ssize_t keylen, vallen;
	int accept_config_total = 4;
	int accept_config[4] = {0, 0, 0, 0};
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
		// arg for thread number
		else if(strcmp("thread", key) == 0) {
			server->arg.nthread = atoi(val);
			accept_config[2] = 1;
		}
		// arg for run path
		else if(strcmp("run_path", key) == 0) {
			if (vallen <= sizeof(server->arg.run_path)) {
				strncpy(server->arg.run_path, val, vallen);
				accept_config[3] = 1;
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

// clean the request because these will be sent again
static int clean_request(csiebox_server* server, int conn_fd) {
	csiebox_protocol_header header;
	csiebox_protocol_login req;
	csiebox_protocol_meta meta;
	csiebox_protocol_rm rm;
	memset(&header, 0, sizeof(header));
	char buf[PATH_MAX];
	memset(buf, 0, PATH_MAX);
	if(recv_message( conn_fd, &header, sizeof(header) ) <= 0) {
		logout(server, conn_fd);
		return -1;
	}
	switch (header.req.op) {
		case CSIEBOX_PROTOCOL_OP_LOGIN:
			complete_message_with_header(conn_fd, &header, &req);
			return 0;
		case CSIEBOX_PROTOCOL_OP_SYNC_META:
			complete_message_with_header(conn_fd, &header, &meta);
			recv_message(conn_fd, buf, meta.message.body.pathlen);
			return 0;
		case CSIEBOX_PROTOCOL_OP_SYNC_END:
			return 0;
		case CSIEBOX_PROTOCOL_OP_RM:
			complete_message_with_header(conn_fd, &header, &rm);
			recv_message(conn_fd, buf, rm.message.body.pathlen);
			return 0;
		default:
			return 0;
	}    
}

static int handle_request(csiebox_server* server, int conn_fd) {
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	if(recv_message( conn_fd, &header, sizeof(header) ) <= 0) {
		fprintf(stderr, "logout or error\n");
		logout(server, conn_fd);
		return -1;
	}
	switch (header.req.op) {
		case CSIEBOX_PROTOCOL_OP_LOGIN:
			fprintf(stderr, "login\n");
			csiebox_protocol_login req;
			if (complete_message_with_header(conn_fd, &header, &req)) {
				login(server, conn_fd, &req);
			}
			return 0;
		case CSIEBOX_PROTOCOL_OP_SYNC_META:
			fprintf(stderr, "sync meta\n");
			csiebox_protocol_meta meta;
			if (complete_message_with_header(conn_fd, &header, &meta)) {
				sync_file(server, conn_fd, &meta);
			}
			return 0;
		case CSIEBOX_PROTOCOL_OP_SYNC_END:
			fprintf(stderr, "sync end\n");
			return 0;
		case CSIEBOX_PROTOCOL_OP_RM:
			fprintf(stderr, "rm\n");
			csiebox_protocol_rm rm;
			if (complete_message_with_header(conn_fd, &header, &rm)) {
				rm_file(server, conn_fd, &rm);
			}
			return 0;
		default:
			fprintf(stderr, "unknow op %x\n", header.req.op);
			return 0;
	}    
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

static void sync_file(csiebox_server* server, int conn_fd, csiebox_protocol_meta* meta) {
	csiebox_client_info* info = server->client[conn_fd];
	char* homedir = get_user_homedir(server, info);
	printf("homedir = %s\n", homedir);
	char buf[PATH_MAX], req_path[PATH_MAX];
	memset(buf, 0, PATH_MAX);
	memset(req_path, 0, PATH_MAX);
	recv_message(conn_fd, buf, meta->message.body.pathlen);
	sprintf(req_path, "%s%s", homedir, buf);
	free(homedir);
	fprintf(stderr, "req_path: %s\n", req_path);
	struct stat stat;
	memset(&stat, 0, sizeof(struct stat));
	int need_data = 0, change = 0, lock = 1;
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
			struct flock fl = {F_WRLCK, SEEK_SET, 0, 0, 0};
			fl.l_pid = getpid();
			// fail to lock the file
			if(fcntl(fd, F_SETLK, &fl) == -1)	lock = 0;
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
				if (fd > 0 && lock) {
					write(fd, buf, readlen);
				}
			}
			// unlock and close
			if (fd > 0)	close(fd);
			if(lock) {
				fl.l_type = F_UNLCK;
				fcntl(fd, F_SETLK, &fl);
			}
		}
		// return block if lock fail
		if(lock == 0) {
				header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
				header.res.status = CSIEBOX_PROTOCOL_STATUS_BLOCK;
				send_message( conn_fd, &header, sizeof(header) );
				return;
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

static void rm_file(csiebox_server* server, int conn_fd, csiebox_protocol_rm* rm) {
	csiebox_client_info* info = server->client[conn_fd];
	char* homedir = get_user_homedir(server, info);
	char req_path[PATH_MAX], buf[PATH_MAX];
	memset(req_path, 0, PATH_MAX);
	memset(buf, 0, PATH_MAX);
	recv_message(conn_fd, buf, rm->message.body.pathlen);
	sprintf(req_path, "%s%s", homedir, buf);
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

static void handle_user1(int _signal, siginfo_t *_info, void *_context) {
	fprintf(stderr, "[Signal]User1\n");
	uint32_t active = 0;
	for(int i = 0 ; i < nthread ; i++)	if(data[i]->conn_fd != 0)	active++;
	int fd = open(fifo_path, O_WRONLY);
	if(fd < 0) {
		fprintf(stderr, "Error: Open Fifo\n");
		exit(EXIT_FAILURE);
	}
	active = htonl(active);
	write( fd, &active, sizeof(uint32_t) );
	close(fd);
	fprintf(stderr, "[Signal]Finish Writing Number of Current Active Threads\n");
}

static void handle_term(int _signal, siginfo_t *_info, void *_context) {
	fprintf(stderr, "[Signal]Term\n");
	unlink(fifo_path);
	exit(0);
}

static void handle_int(int _signal, siginfo_t *_info, void *_context) {
	fprintf(stderr, "[Signal]Int\n");
	unlink(fifo_path);
	exit(0);
}

static void daemonize(csiebox_server *_server) {
	pid_t pid;
	// create new process
	pid = fork();
	if(pid == -1) {
		fprintf(stderr, "Error: Fork\n");
		exit(-1);
	}
	else if(pid != 0) {
		// write pid to csiebox_server.pid
		fprintf(stderr, "Parent Pid = %ld, Daemon Pid = %ld\n", (long)getpid(), (long)pid);
		char pid_string[64], pid_path[PATH_MAX];
		memset(pid_path, 0, sizeof(char) * PATH_MAX);
		strcpy(pid_path, _server->arg.run_path);
		if(pid_path[strlen(pid_path) - 1] == '/')	strcat(pid_path, "csiebox_server.pid");
		else	strcat(pid_path, "/csiebox_server.pid");
		int fd = open(pid_path, O_WRONLY);
		sprintf(pid_string, "%ld", (long)pid);
		write( fd, pid_string, strlen(pid_string) );
		close(fd);
		// exit the parent program
		exit(EXIT_SUCCESS);
	}
	// change file mode mask
	umask(0);
	// create new session and process group
	if(setsid() == -1)	exit(-1);
	// set the working directory to the root directory
	if(chdir("/") == -1)	exit(-1);  
	// close all open files--NR_OPEN is overkill, but works
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	// redirect fd's 0,1,2 to /dev/null
	open("/dev/null", O_RDWR);  
	dup(0);
	dup(0);  
	return;
}
