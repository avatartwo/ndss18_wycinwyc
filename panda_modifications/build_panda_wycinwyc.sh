
BUILDPATH=/home/`whoami`/wycinwyc_panda/panda
SOURCEPATH=`pwd`/avatar-panda

mkdir -p $BUILDPATH

# 0) Get dependencies (known to work for ubuntu 16.04)
sudo sh -c 'echo "deb-src http://archive.ubuntu.com/ubuntu/ xenial-security main restricted" >> /etc/apt/sources.list'
sudo apt-get update
sudo apt-get build-dep -y qemu

# panda-specific deps below, taken from panda/scripts/install_ubuntu.sh
sudo apt-get -y install python-pip git protobuf-compiler protobuf-c-compiler \
		libprotobuf-c0-dev libprotoc-dev libelf-dev libc++-dev pkg-config
sudo apt-get -y install software-properties-common
sudo add-apt-repository -y ppa:phulin/panda
sudo apt-get update
sudo apt-get -y install libdwarf-dev python-pycparser


# 1) Fetch PANDA 
#cd `dirname "$BASH_SOURCE"`
git submodule update --init avatar-panda
cd avatar-panda
git submodule update --init dtc
cd ..


# 2) Copy everything to the right directories
cp -r ./wycinwyc ./avatar-panda/panda/plugins
cp ./stm32l1xx_usart/stm32l1xx_usart.c ./avatar-panda/hw/char
cp ./stm32l1xx_usart/stm32l1xx_usart.h ./avatar-panda/include/hw/char


# 3) Make sure our stuff will be built
cd avatar-panda
echo "CONFIG_STM32L1XX_USART=y" >> default-configs/arm-softmmu.mak
echo "obj-\$(CONFIG_STM32L1XX_USART) += stm32l1xx_usart.o" >> hw/char/Makefile.objs
bash -c 'echo -e "\nwycinwyc"' >> panda/plugins/config.panda

# 3.5) Fetch and build libcapstone4 (the wycinwyc panda-plugins require libcapstone4)
cd /home/vagrant/
git clone --branch 4.0-alpha5 https://github.com/aquynh/capstone.git
cd capstone
./make.sh
sudo ./make.sh install


# 4) Configure and make PANDA!
cd $BUILDPATH
$SOURCEPATH/configure --disable-sdl --target-list=arm-softmmu --enable-pyperipheral2
make -j4
