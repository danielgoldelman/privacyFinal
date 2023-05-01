# privacyFinal

Open 3 terminals at the root of this file

In the first terminal write:
``` go run server/main.go 1234 ```

You will not touch this terminal again until the very end.


In the second terminal write:
``` go run auctioneer/main.go 127.0.0.1:1234 ```

It will ask for a few things. Complete them until there are no further prompts on the screen. 




In the third terminal write:
``` go run client/main.go 127.0.0.1:1234 ```

It will ask for a few things, then show "Welcome! List of items: {items from the auctioneer inputs}



You can then write things in the thirdterminal, which will be sent to the other terminals and printed. If you choose to open up other client terminals, they will behave the same as terminal 3.


A few notes:

- Denomination does not matter yet
- Auctioneer has to join before a client can, otherwise it will reject the connection

- long term storage and encryption

- Number of things still has some bugs...

- we dont want usernames to include ":" or "#"
- Stop there from being two users of the same username