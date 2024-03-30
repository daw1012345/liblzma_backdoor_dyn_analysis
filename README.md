# liblzma_backdoor_dynamic_analysis

## Description

The purpose of this repo is to simplify the dynamic analysis of the liblzma backdoor. It imitates the environment that the backdoor is expecting during compilation and linking.

## Instructions
1. Download the backdoor file and extract it. It can be found [here](https://www.openwall.com/lists/oss-security/2024/03/29/4/2) (`$ wget https://www.openwall.com/lists/oss-security/2024/03/29/4/2 -O backdoor.gz && gzip -d backdoor.o.gz`)
2. Build it with the build.sh file. (`$ bash build.sh`)
3. Analyze run the resulting file in a debugger. (`$ gdb backdoored_file`)

## IMPORTANT INFORMATION
I have not verified that this works. I don't recommend running this on your machine (although it is believed that the backdoor only targets openssh). 
I provide no guarantees or warranty. I am not responsible if this breaks something!
