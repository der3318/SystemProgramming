# SP15MP4
#### Student ID
b03902015


#### Program Usage
The goal iof this assignment is to enable multiple clients by pthreads.
Hence, I practice on using thread pool, mutex and file lock.
This assignment consists of three sub-assignments.
* Server: Use thread to handle request
* Apply lock when upload file
* Client: Handle server returned status


#### Sample execution
###### Compile  
`make -C src clean`
`make -C src`


###### Run  
1. Modify `server.cfg`, `client.cfg`, `account` in `config`
2. run `$./bin/csiebox_server ./config/server.cfg` on server
3. run `$./bin/csiebox_client ./config/client.cfg` on client


