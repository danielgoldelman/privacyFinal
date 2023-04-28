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
- Number of things still has some bugs...
- Validation of user input has to happen
    - we dont want usernames to include ":" or "@"
    - prices input and submitted by clients should be larger than the current bid cap (and larger than the starting price set by the auctioneer)
- Stop there from being two auctioneers
- Stop there from being two users of the same username
- set up auction for multiple items
- let auctioneer input affect the standing of the auction (auction for an item closes)
- keep record of who won what auction and their username (later email address as well???)
- on auction close, every connection is severed