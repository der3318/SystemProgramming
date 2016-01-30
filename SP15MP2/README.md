# SP15MP2
#### Student ID
b03902015


#### Program Usage
I complete the process for linking my local repository to a newly created CSIEbox account.

Hence, the process will synchronize the files and directories under client’s local repository, which may or may not be empty, to the server, which is empty.

When the process completes, the content of the directories on client side and server must be identical.

The process consists of following steps:

**Scan the directory**:
```
The process traverses/scans the local repository directory to find out the existed files and directories, and do the synchronization. 

In this step, the process starts from the top of local repository and transmits all the files and directories to the server side.

I use the provided socket communication template to transmit the files and handle the operations for maintaining directories including creating directories, reconstructing soft/hard link on the server sides, etc.
```
**Monitor the changes on files, directories, hard link, and soft link on local repository**:
```
To keep the file/directories to be up-to-date with the local repository, the process has to monitor if there is any change on files/directories.

For this purpose, I use inotify API, which can monitor file system events.

Example program of using inotify API is available in the provided package, which is inotify_test.c.
```


#### Sample execution
###### Compile  
`make -C src clean`
`make -C src`


###### Run  
1. Modify `server.cfg`, `client.cfg`, `account` in `config`
2. run `$./bin/csiebox_server ./config/server.cfg` on server
3. run `$./bin/csiebox_client ./config/client.cfg` on client


