# privacyFinal

Open 3 terminals at the root of this file


### Server
In the first terminal write:
``` go run server/main.go 1234 ```

You will not touch this terminal again until the very end.

### Auctioneer
In the second terminal write:
``` go run auctioneer/main.go 127.0.0.1:1234 ```

It will ask for a few things. Complete them until there are no further prompts on the screen. 

### Clients
In the third terminal write:
``` go run client/main.go 127.0.0.1:1234 ```

It will ask for a few things, then show "Welcome! List of items: {items from the auctioneer inputs}



You can then write bids in the third terminal, which will be sent to the other terminals and printed. If you choose to open up other client terminals, they will behave the same as terminal 3.

## TO BUILD (MAC)
cd to correct folder

valid GOOS for this project: `darwin` or `windows`
valid GOARCH for this project: `arm64` or `amd64`
`GOOS={os} GOARCH={arch} go build -o {folder}_{os flag}_{arch flag} main.go`

## IF RUNNING ON MULTIPLE (MAC) COMPUTERS:
Download the right executable, and option click the file. Select open, and click yes to all popups. Open a terminal and cd to the file's folder. Then run `chmod u+x {file}_D_{os}` to allow the file to be run. Then you can run the file using `{file}_D_{os} {ip of server computer}`. Note: May need to check network settings to verify ip addr


A few notes:

- Auctioneer has to join before a client can, otherwise it will reject the connection
