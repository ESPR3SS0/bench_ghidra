
sudo apt install -y openjdk-17-jre
sudo apt install -y wget 
sudo apt install -y unzip

echo "Done installing deps"

if [ -d "$HOME/ghidra_10.3.3_PUBLIC" ]; then 
    rm -rf ~/ghidra_10.3.3_PUBLIC
fi

if [ -f "$HOME/ ghidra_10.3.3_PUBLIC_20230829.zip" ]; then
    rm "$HOME/ ghidra_10.3.3_PUBLIC_20230829.zip"
fi

cd ~ && wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.3_build/ghidra_10.3.3_PUBLIC_20230829.zip
cd ~ && unzip ghidra_10.3.3_PUBLIC_20230829.zip

echo "Installed ghidra"



