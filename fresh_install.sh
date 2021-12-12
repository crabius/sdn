# script to get ryu and mininet integration up and 
# running on a fresh VM install. Note this assumes an ubuntu VM.

# install packages and grab repo
echo "installing packages..."
sudo apt-get update 
sudo apt install git
sudo apt-get install vim
sudo apt-get install python3-pip
sudo apt-get install mininet
sudo apt install python3-ryu

#grab repo with custom scripts
echo "grabbing sdn repo and installing custom scripts"
git clone https://github.com/crabius/sdn
#have to include a script with a bugfix that has not been updated on the ryu github 
#but is on the ryu forums
cp ./sdn/ofp_handler.py /usr/lib/python3/dist-packages/ryu/controller/ofp_handler.py 

echo "starting mininet in background. To interact with mininet rerun this command in another tab before you run ryu."
# run mininet controller
sudo mn --controller=remote --topo=single,3 --switch=ovsk,protocols=OpenFlow10 --mac &

echo "starting ryu controller"
# run ryu controller
ryu-manager ./sdn/ss13_commented.py
