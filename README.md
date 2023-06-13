# omnisette-server

**An HTTP server wrapper for [omnisette](https://github.com/SideStore/apple-private-apis).**

Supports both V1 (Provision) and V3 of anisette servers.

![Alt](https://repobeats.axiom.co/api/embed/f63664cd6a9a808ffcf3336001087d474ddb86f4.svg "Repobeats analytics image")

## Setup

First, [download the Apple Music APK](https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk) in the root of the project directory and then extract it as a zip.

```bash
unzip applemusic.apk 'lib/*/libstoreservicescore.so' 'lib/*/libCoreADI.so'
```

Next, [download the latest omnisette-server binary for your platform from GitHub Releases](https://github.com/SideStore/omnisette-server/releases). Place it in the root project directory with the `lib`
directory, so that omnisette can access the libraries at `./lib`. (You can also run from source via `cargo run`)

Now, run the omnisette-server binary. You can use `--help` to get a list of options, but the defaults should be good for most setups (I recommend changing the `worker` argument; it is equal to the
amount of people who can provision at the same time, so choose it based on how much traffic you expect). You might want to setup something to run omnisette-server in the background.

## Compile

If you wish to build omnisette-server, run the following:

```bash
sudo apt update
sudo apt install --no-install-recommends -y git unzip curl perl make
curl https://sh.rustup.rs -sSf | sh # Choose option 1
source "$HOME/.cargo/env"
git clone https://github.com/SideStore/omnisette-server.git
cd omnisette-server
cargo build --release
curl https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk -O
unzip applemusic.apk 'lib/*/libstoreservicescore.so' 'lib/*/libCoreADI.so'
rm applemusic.apk
./target/release/omnisette-server
```

## Docker

Run:

```bash
docker run -p 6969:80 --volumes omnisette_data:/opt/omnisette-server/lib ghcr.io/sidestore/omnisette-server:latest
```

Or if you want to build it locally, clone the repository and then run:

```bash
docker build . -t imagenameofyourchoosing
docker run -p 6868:80 --entrypoint=/bin/bash -it imagenameofyourchoosing
```
