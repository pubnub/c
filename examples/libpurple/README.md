A pubnub plugin for Pidgin, Adium and other libpurple based messengers.

# Building
    $ sudo apt-get install libpurple-dev libevent-dev libjson0-dev libcurl4-openssl-dev libssl-dev
    $ git clone git://github.com/pubnub/c
    $ cd c
    $ make
    $ sudo make install
    $ cd examples/libpurple
    $ make deb # optionaly
    $ sudo make install

And now, restart Pidgin.

# Configuration
Now that it installed, here’s how to configure it for your account:

 * Open “Manage Accounts”.
 * Click “New…”
 * Select the “Pubnub” protocol.
 * Enter your username and the publish/subscribe keys.
 * Save the account.
 * Now you can send/receive messages on channels (chat rooms).

