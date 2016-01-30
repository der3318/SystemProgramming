# SP15MP5
#### Student ID
b03902015


#### Program Usage
* Communicating with server monitor
* Daemonizing your applications on server


#### Sample execution
###### Compile  
`make -C src clean`
`make -C src`


###### Run  
1. Modify `server.cfg`, `client.cfg`, `account` in `config`
2. run `$cd script; ./csiebox_server.sh start; cd ..` on server
3. run `$cd web; nodejs app.js; cd ..` on server
4. run `$./bin/csiebox_client ./config/client.cfg` on client
5. run `$cd script; ./csiebox_server.sh stop; cd ..` on server

