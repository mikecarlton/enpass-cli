# Installation
These are macOS-specific (tested on Sierra 10.12.4)

## Prerequisites

```
go get -v -u github.com/mattn/go-sqlite3
go get -v -u github.com/xeodou/go-sqlcipher
```

You must provide openssl headers for go-sqlcipher to build

```
brew install openssl
```

and then link openssl into go-sqlcipher, e.g

```
cd ~/go/src/github.com/xeodou/go-sqlcipher
ln -s /usr/local//Cellar/openssl/1.0.2i/include/openssl .
```

Now you can install the packages

```
cd ~/go/src/github.com/mattn/go-sqlite3
go install -v -tags 'libsqlite3 darwin' \
   -ldflags '-L /usr/local/opt/sqlite/lib' \
   -gcflags '-I /usr/local/opt/sqlite/include' 
```

```
cd ~/go/src/github.com/xeodou/go-sqlcipher
go install -v -tags 'libsqlite3 darwin' \
   -ldflags '-L /usr/local/opt/sqlite/lib' \
   -gcflags '-I /usr/local/opt/sqlite/include'
```

## Building and Running the program

Working in the enpass-cli directory

```
cd enpass-cli
```

### Running

```
go run -tags 'libsqlite3 darwin' enpass-cli.go ARGUMENTS
```

### Building

```
go build -v -tags 'libsqlite3 darwin'
./enpass-cli ARGUMENTS
```

### Debugging

Use [godebug](http://blog.mailgun.com/introducing-a-new-cross-platform-debugger-for-go/).  First install it:

```
go get -u github.com/mailgun/godebug
```

Then insert breakpoints, e.g. `_ = "breakpoint"` and

```
godebug run -tags 'libsqlite3 darwin' enpass-cli.go ARGUMENTS
```

# Accessing the Enpass DB

You can access the database via sqlite3 cli.

## Installation

```
brew install sqlite3
brew install sqlcipher
```

## Sqlite3 CLI

```
sqlcipher <file>
PRAGMA cipher_default_kdf_iter = 24000;
PRAGMA kdf_iter = 24000;
PRAGMA key = '<password>';
```

## Reference
[Enpassant.py](https://github.com/steffen9000/enpass-decryptor/blob/master/Enpassant.py)
