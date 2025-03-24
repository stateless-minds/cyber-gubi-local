# cyber-gubi-local - the local daemon needed to run cyber-gubi

## Requirements

+ Linux
+ go

## Features

+ One user per device
+ Portable keys, when you change device simply copy the generated encrypted_aes_key.bin to your new device
+ For businesses - you can add as many associates as you want on the same device


## Instructions

+ `export ENC_PASSWORD=your_password_here`
+ `unzip ipfs.zip`
+ `./ipfs daemon --enable-pubsub-experiment`
+ `./main`
