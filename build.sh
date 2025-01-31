sudo apt update -y
sudo apt install libelf-dev -y
sudo apt install libcapstone-dev
gcc -o 156dbg 156dbg.c -lelf -lcapstone 

sudo ln -s $(pwd)/156dbg /usr/local/bin/156dbg
