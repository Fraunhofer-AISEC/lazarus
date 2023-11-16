#!/usr/bin/bash

mkdir -p updates

if [ ! -f $1 ]; then
	echo "Please provide path to tarball."
	echo "Usage: ./yocto/deploy_tarball.sh <tarball>"
	exit 1
fi

tar xvf $1 --strip-components=2 lmp-arp-binaries/ih_tools/fit_config_hash

tar xvf $1 -C updates --strip-components=1 lmp-arp-binaries/fitImage-production-image-apalis-imx8-apalis-imx8
tar xvf $1 -C updates --strip-components=1 lmp-arp-binaries/fitImage-downloader-image-apalis-imx8-apalis-imx8
tar xvf $1 -C updates --strip-components=1 lmp-arp-binaries/u-boot-apalis-imx8.itb
tar xvf $1 -C updates --strip-components=1 lmp-arp-binaries/imx-boot-apalis-imx8

cd updates
mv fitImage-production-image-apalis-imx8-apalis-imx8 productionImage
mv fitImage-downloader-image-apalis-imx8-apalis-imx8 downloaderImage
mv u-boot-apalis-imx8.itb u-boot.itb
mv imx-boot-apalis-imx8 imx-boot

version=$(date '+%s')

python3 ../yocto/create_update_file.py download $version 1 1 1 1
python3 ../yocto/create_update_file.py production $version 1 1 1 1
python3 ../yocto/create_update_file.py bootloader_proper $version 1 1 1 1
python3 ../yocto/create_update_file.py bootloader_early $version 1 1 1 1
