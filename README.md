# summer-project

I am doing a summer project for the compsci department at VUW.
The aim of my project is to document the process for integrating the network traffic analyser Zeek with a software defined network controller (Like Ryu). By doing this, we can detect suspicious traffic and then quarantine malicious hosts.

Right now there is a basic integration between ryu and mininet. You can run a mininet virtual network of 3 hosts that are connected to a switch. The switch is controlled by a Ryu controller via the OpenFlow protocol. 

```Bash
sudo ./fresh_install.sh
```

The Ryu controller implements a learning switch or "smart switch", which learns to associate MAC addresses with output interfaces in real time for more efficient packet forwarding. It also blocks traffic between hosts 2 and 3. This was just a wee excersize to get me up to speed with writing ryu applications. Note that this bash script assumes you are running it on a fresh ubuntu VM.
