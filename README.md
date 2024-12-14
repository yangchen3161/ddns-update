# ddns-update client 
### 
A ddns client that runs under Windows developed with AI code assistant
In the IPv4 era, DDNS clients can run on servers or routers, and other machines can access them through NAT. In the IPv6 era, if a device needs to report its own IPv6 address, it needs to run the DDNS client on the device. It supports multiple different DDNS service providers and can run on Windows-X86 is relatively rare, so I wrote one for myself with an AI code assistant, considering that there may be other people who need it as much as I do, I put the code and the compiled exe single file here, and those who need it can use it.  



### How to Use  
After downloading the archive from the releases page, modify the “config.ini” , and then run the “ddns-update.exe” directly. This program also supports running without interface, adding the parameter "-noconsole", which is suitable for use in Windows scheduled tasks.  

### Configuration config.ini    
All custom configurations are in the config.ini, the program cannot run correctly if the settings are incorrect, and multiple different ddns service provider configurations can be set, which is suitable for all service providers who update the dynamic domain name IP through HTTP  

[general]  
If the DDNS update is 0 , the program will exit directly after the update, which is suitable for a scheduled start task  
period = 0  
#Obtain the external IPv4 address of the machine through the 4.ipw.cn, and replace it with the address of another service provider that returns plain text  
ipv4-api = https://4.ipw.cn/  
#Obtain the external IPv6 address of the machine through the 6.ipw.cn, and replace it with the address of another service provider that returns plain text  
ipv6-api = https://6.ipw.cn/  

The name of the service provider can be distinguished by ":1" and ":2" to distinguish different domain names of the same service provider  
[freedns.afraid.org]  
update-ip tells the program whether you need to update the IPv4 or IPv6 address of this domain, either only one or both  
update-ip = ipv4  
username usually stands for username, but it can also be a value that is defined by other values, such as domain name prefixes  
username = username  
password generally represents password, and can also be the value of update token  
password = password or token  
hostnaime is the full domain name, not just the prefix  
hostname = hostname  
The server of the update URL does not need to write http://, and uses https by default  
ddns-server = sync.afraid.org  
ddns-path is spliced according to the updated URL of your DDNS provider, %u instead of username, %p instead of password, %h instead of hostname, %i4 instead of ipv4 address, %i6 instead of ipv6 address  
ddns-path = /u/?u=%u&p=%p&h=%h&ip=%i4  
