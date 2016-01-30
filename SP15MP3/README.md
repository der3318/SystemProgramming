# SP15MP3
#### Student ID
b03902015


#### Program Usage
The goal of this assignment is to enable multiple clients and relink CSIEBox account on a new computing device.
Hence, I practice on using multiplexing IO.
This assignment consists of two sub-assignments and one bonus assignment.
* First sub-assignment: IO Multiplexing on servers
* Second sub-assignment: File Download
* Bonus Assignment: Bouncing Problem of multiple client devices


#### Sample execution
###### Compile  
`make -C src clean`
`make -C src`


###### Run  
1. Modify `server.cfg`, `client.cfg`, `account` in `config`
2. run `$./bin/csiebox_server ./config/server.cfg` on server
3. run `$./bin/csiebox_client ./config/client.cfg` on client


