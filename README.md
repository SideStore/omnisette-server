# omnisette-server

**An HTTP server wrapper for [omnisette](https://github.com/SideStore/apple-private-apis).**

Supports both V1 (Provision) and V3 of anisette servers.

![Alt](https://repobeats.axiom.co/api/embed/f63664cd6a9a808ffcf3336001087d474ddb86f4.svg "Repobeats analytics image")

## Setup

First, [download the Apple Music APK](https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk) and extract it as a zip. (`cd tmp && unzip ../applemusic.apk`) Then, move the `lib`
directory to the directory you want to run omnisette-server from.

Next, [download the latest omnisette-server binary for your platform from GitHub Releases](https://github.com/SideStore/omnisette-server/releases). Place it in the same directory with the `lib`
directory, so that omnisette can access the libraries at `./lib`. (You can also run from source via `cargo run`)

Now, run the omnisette-server binary. You can use `--help` to get a list of options, but the defaults should be good for most setups (I recommend changing the `worker` argument; it is equal to the
amount of people who can provision at the same time, so choose it based on how much traffic you expect). You might want to setup something to run omnisette-server in the background.
