# 1) Install the ykush
sudo apt-get install -y libudev-dev
git submodule update --init deps/ykush
cd deps/ykush
./build.sh
sudo ./install.sh
cd ../../

# 2) fetch and install python dependencies
sudo pip2 install boofuzz
sudo pip2 install numpy
sudo pip2 install pyelftools
sudo pip2 install tabulate

# 3) generate funcs.json from the debug symbols contained in expat_panda.elf
python2 ./scripts/debug_symbols.py ./binaries/expat_panda.elf

# 4) Let's add udev-rules, so that we can run the experiments without root
sudo sh -c 'cat > /etc/udev/rules.d/04-ykush.rules' << EOF
SUBSYSTEMS=="usb", ATTRS{idVendor}=="04d8", ATTRS{idProduct}=="f2f7", \\
    MODE:="0666", \\
    SYMLINK+="ykush_%n"
EOF

sudo sh -c 'cat > /etc/udev/rules.d/49-stlinkv2-1.rules' << EOF
SUBSYSTEMS=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="374b", \\
    MODE:="0666", \\
    SYMLINK+="stlinkv2-1_%n"
EOF

sudo udevadm control --reload-rules

# 4.5) We need to be in the group dialout to access /dev/ttyUSB0
sudo adduser $USER dialout
