##PubNub plugin for Pidgin, Adium and other libpurple based messengers.

###Components
In general, for each chat client, you will be dealing with two main components:

* The PubNub common library
* The chat-client specific plugin (Adium, Pidgin/Finch)

#### Adium (Mac Only)
The XCode project source for Adium can be found at https://github.com/pubnub/c/tree/master/examples/libpurple
(Be sure you have installed the PubNub libpurble client before trying to run the plugin.)

#### Building Pidgin/Finch plugin for Linux
1. $ sudo apt-get install libpurple-dev libevent-dev libjson0-dev libcurl4-openssl-dev libssl-dev
1. $ git clone git://github.com/pubnub/c
1. $ cd c
1. $ make
1. $ sudo make install
1. $ cd examples/libpurple
1. $ make deb # optionaly
1. $ sudo make install

#### Building Pidgin/Finch for Mac
1. $ install macports (macports.org) 
1. $ sudo port install pidgin +finch 
1. $ sudo port install json-c 
1. $ sudo port install libevent 
1. $ git clone https://github.com/pubnub/c.git 
1. $ cd c/libpubnub 
1. $ make -f Makefile.darwin 
1. $ sudo make -f Makefile.darwin install 
1. $ cd ../examples/libpurple 
1. $ make 
1. $ mkdir -p ~/.purple/plugins 
1. $ cp libpubnub.so ~/.purple/plugins

#### Configuration (Common for Mac and Linux)
Now that it installed, here’s how to configure it for your account:

 * Restart Pidgin.
 * Open “Manage Accounts”.
 * Click “New…”
 * Select the “Pubnub” protocol.
 * Enter your username and the publish/subscribe keys.
 * Save the account.
 * Now you can send/receive messages on channels (via join a chat room).

