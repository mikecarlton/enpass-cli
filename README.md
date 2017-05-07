# Installation
These are macOS-specific (tested on Sierra 10.12.4)

## Prerequisites

```
go get -v -u github.com/mattn/go-sqlite3
go get -v -u github.com/xeodou/go-sqlcipher
go get github.com/keybase/go-keychain
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
Details of accessing the encrypted fields came from [Enpassant.py](https://github.com/steffen9000/enpass-decryptor/blob/master/Enpassant.py)

### DB Structure

```
sqlite> .tables
Attachment        Folder_Cards      Password_History
Cards             Folders           Pool
Favorites         Identity          SecuritySettings
```

```
sqlite> .schema
CREATE TABLE Identity(ID INTEGER PRIMARY KEY AUTOINCREMENT CHECK (ID=1), Version INTEGER, Signature TEXT, Sync_UUID TEXT, Hash TEXT, Info BLOB);
CREATE TABLE Cards (ID INTEGER PRIMARY KEY AUTOINCREMENT,Title TEXT,SubTitle TEXT, Type TEXT,Category TEXT, IconID INTEGER,CustomIconId TEXT, UpdateTime INTEGER, UUID TEXT UNIQUE NOT NULL,Data BLOB, Trashed INTEGER,Deleted INTEGER,Urls TEXT,FormFields TEXT);
CREATE TABLE Favorites (ID INTEGER PRIMARY KEY AUTOINCREMENT,CardUUID TEXT UNIQUE NOT NULL,UpdateTime INTEGER, Trashed INTEGER);
CREATE TABLE Folders (ID INTEGER PRIMARY KEY AUTOINCREMENT,Title TEXT, UpdateTime INTEGER, UUID TEXT UNIQUE NOT NULL,Parent TEXT, Trashed INTEGER, IconID INTEGER);
CREATE TABLE Folder_Cards (ID INTEGER PRIMARY KEY AUTOINCREMENT,FolderUUID TEXT NOT NULL,CardUUID TEXT NOT NULL, UpdateTime INTEGER, Trashed INTEGER);
CREATE TABLE Pool (UID INTEGER UNIQUE,Data BLOB);
CREATE TABLE Password_History (ID INTEGER PRIMARY KEY AUTOINCREMENT,Password TEXT,Timestamp Integer,Domain TEXT);
CREATE TABLE SecuritySettings (ID INTEGER PRIMARY KEY AUTOINCREMENT,Key1 TEXT NOT NULL,Key2 TEXT,Value TEXT, CONSTRAINT UQ_Key1_Key2 UNIQUE(Key1,Key2));
CREATE TABLE Attachment (ID INTEGER PRIMARY KEY AUTOINCREMENT,UUID TEXT UNIQUE,CardUUID TEXT,MetaData TEXT,Data BLOB,Trashed integer,Timestamp integer);
```

```
sqlite> select * from securitysettings;
ID                    Key1                  Key2                  Value
--------------------  --------------------  --------------------  ----------
1                     AppLockOnSystemLock                         0
2                     AppLockOnSystemSleep                        1
3                     ClearClipBoard                              1
4                     IdleTimeType                                1
5                     IdleTimeValue                               15
6                     IsHidePassword                              1
7                     clearClipboardInterv                        30
8                     isLockOnSystemIdle                          1
9                     lock_on_fast_user_sw                        1
10                    lock_on_screensaver                         1
11                    webdav_ssl_cert_dige
12                    webdav_ssl_cert_dige
13                    GOOGLE_DRIVE_REMOTE   AccessToken           SECRET1
14                    GOOGLE_DRIVE_REMOTE   refresh_token         SECRET2
15                    AppLockAtMainWindowC                        1
16                    mac_touch_id                                0
```

```
sqlite> select *, length(info) from identity;
          ID = 1
     Version = 5
   Signature = WalletxDb
   Sync_UUID = 95BADAA1-138B-4085-88C8-3C3847205AD6
        Hash = QrXcYmHAoAK769AG8Vq9Rnjyyt79Lg3b
        Info = <blob ...>
length(info) = 48
```

```
sqlite> select * from attachment;
       ID = 1
     UUID = 6a5d24cc-917a-4f1f-a60e-9de49aa749bc
 CardUUID = 4bbf8c24-7d35-4c0a-bafe-ed04447f8783
 MetaData = {
    "filename": "attach.txt",
    "kind": "text/plain",
    "order": 1,
    "size": 12
}

     Data = Hello world

  Trashed = 0
Timestamp = 1494136077
```
