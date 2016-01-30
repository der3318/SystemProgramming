# SPMP4 Paper Report
* **Student ID** B03902015
* **How to handle multiple client device update same file**
	* We need file lock to prevent multi-process from modifying the same file
	* In `handle_request()`, we should check if there is an existing file with the same filename
	* Since the file on the server is uploaded by another device, we need to merge it with the one from current device
	* When it comes to merging, the first step is to check if the contents are identical
    	1. If Yes, we only need to update the file meta
    	2. Otherwise, we should `merge()` the contents of the two files with the file merger of MP1, using the LCS algoritgm
* **How to use process instead of thread to handle request**
	* In thread-pool model, we have threads with `thread_fun()`
	* If we want to use process, we can use `fork()` in main process, and the child processes will run the `thread_fun()` as we used in thread-pool model
	```c
	void thread_fun() {
		// child process code
	}

	void server_run() {
		int nthread = server->arg.nthread;
		for(int i = 0 ; i < nthread ; i++) {
			pid_t pid = fork();
			if(pid == 0)	thread_fun();
		}
		// main process code
	}
	```
* **Compare throughput of process methed with thread method**
	* The throughput of thread should be better, since threads can share data with each other more easily
	* With `fork()`, different process will have its own memory, and this is the main reason why process method is not as good as thread method
