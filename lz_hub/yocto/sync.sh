#!/usr/bin/bash

base_addr="user@build-server:lmp-arp/build-lmp/deploy/images/apalis-imx8"

rsync -L ${base_addr}/ih_tools/fit_config_hash fit_config_hash

mkdir -p updates && cd updates

rsync -L ${base_addr}/fitImage-production-image-apalis-imx8-apalis-imx8 productionImage
rsync -L ${base_addr}/downloader-image/fitImage-downloader-image-apalis-imx8-apalis-imx8 downloadImage
rsync -L ${base_addr}/imx-boot imx-boot
rsync -L ${base_addr}/u-boot-apalis-imx8.itb u-boot.itb

version=$(date '+%s')

python3 ../yocto/create_update_file.py download $version 1 1 1 1
python3 ../yocto/create_update_file.py production $version 1 1 1 1
python3 ../yocto/create_update_file.py bootloader_proper $version 1 1 1 1
python3 ../yocto/create_update_file.py bootloader_early $version 1 1 1 1
