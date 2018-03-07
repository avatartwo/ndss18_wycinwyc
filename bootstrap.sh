# 1) Install general dependencies
sudo apt-get update
sudo apt-get install -y cmake
sudo apt-get install -y python python-pip
sudo apt-get install -y libc6-i386 gdb git pkg-config gdb-arm-none-eabi

# 2) Fetch and install avatar
cd /home/vagrant/
git clone https://github.com/avatartwo/avatar2.git 
sudo pip2 install avatar2/

# 3) build the endpoints
sudo apt-get install -y openocd

# 3.5) apply wycinwyc to panda
cd /vagrant/panda_modifications
./build_panda_wycinwyc.sh

# 3.6 add symlink to experiments
ln -s /home/vagrant/wycinwyc_panda/panda/ /vagrant/experiments/deps/avatar-panda


# 4) setup experiment
cd /vagrant/experiments
./setup_experiments.sh
