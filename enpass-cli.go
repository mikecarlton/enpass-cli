
package main

/*
  go get -v -u github.com/mattn/go-sqlite3
  go get -v -u github.com/xeodou/go-sqlcipher
  <link openssl into go-sqlcipher>
    openssl -> /usr/local//Cellar/openssl/1.0.2i/include/openssl

  cd .../go-sqlite3
  go install -v -ldflags '-L /usr/local/opt/sqlite/lib' -gcflags '-I /usr/local/opt/sqlite/include' -tags 'libsqlite3 darwin'

  cd .../go-sqlcipher
  go install -v -ldflags '-L /usr/local/opt/sqlite/lib' -gcflags '-I /usr/local/opt/sqlite/include' -tags 'libsqlite3 darwin'

  go build -v -tags 'libsqlite3 darwin'

  # by hand:
  sqlcipher <file>
  PRAGMA cipher_default_kdf_iter = 24000;
  PRAGMA kdf_iter = 24000;
  PRAGMA key = '<password>';

  # reference:
  # https://github.com/steffen9000/enpass-decryptor/blob/master/Enpassant.py
*/

import (
    "os"
//    "log"
//    "flag"
    "fmt"
    "encoding/json"
    "crypto/cipher"
    "crypto/aes"
    "crypto/sha256"
    "golang.org/x/crypto/pbkdf2"
    "golang.org/x/crypto/ssh/terminal"
    "database/sql"
    _ "github.com/xeodou/go-sqlcipher"
)

func check(err error) {
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}

func generateKey(hash, salt []byte) (key []byte) {
    key = pbkdf2.Key(hash, salt, 2, 32, sha256.New)

    return key
}

func getCryptoParams(db *sql.DB) (iv, key []byte) {
    var id, version, signature, sync_uuid string
    var hash, info []byte

    row := db.QueryRow("SELECT * FROM Identity")
    err := row.Scan(&id, &version, &signature, &sync_uuid, &hash, &info)
    check(err)

    iv = info[16:32]
    salt := info[32:48]
    key = generateKey(hash, salt)

    return iv, key
}

func openDb(db_file string) (db *sql.DB) {
    db, err := sql.Open("sqlite3", db_file)
    check(err)

    /*
    t := terminal.NewTerminal(os.Stdin, "> ")
    password, err := t.ReadPassword("Password: ")
    */
    password, ok := os.LookupEnv("ENPASS_PASSWORD")
    if !ok {
        fmt.Print("Password: ")
        password_bytes, err := terminal.ReadPassword(0)
        check(err)
        password = string(password_bytes)
        fmt.Println()
    }

    err = db.Ping()
    check(err)

    _, err = db.Exec(fmt.Sprintf("PRAGMA key = '%v';", password))
    check(err)

    _, err = db.Exec("PRAGMA cipher_default_kdf_iter = 24000;")
    check(err)

    _, err = db.Exec("PRAGMA kdf_iter = 24000;")
    check(err)

    return db
}

func decrypt(data, iv, key []byte) (card_json []byte) {
    block, err := aes.NewCipher(key)
    check(err)

    if len(data) % aes.BlockSize != 0 {
        panic("ciphertext is not a multiple of the block size")
    }

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(data, data)

    pad_bytes := int(data[len(data)-1])
    card_json = data[:len(data)-pad_bytes]

    return card_json
}

type History struct {
    Updatetime string
    value string
}

type Field struct {
    History []History
    Isdeleted int
    Label string
    Sensitive int
    Type string
    Uid string
    Updatetime string       // really a date
    Value string
}

type Card struct {
    Fields []Field
    Iconid int64
    Name string
    Note string
    Templatetype string
    Updatetime string       // really a date
    Uuid string
}

func getCards(db *sql.DB, iv, key []byte) {
    rows, err := db.Query("SELECT title, subtitle, data " +
                           "FROM Cards " +
                           "WHERE deleted = 0 AND trashed = 0 LIMIT 10")
    check(err)
    defer rows.Close()

    for rows.Next() {
        var (
            title string
            subtitle string
            data []byte
        )

        err := rows.Scan(&title, &subtitle, &data)
        check(err)

        card_json := decrypt(data, iv, key)
        // fmt.Println(title)
        // fmt.Println(subtitle)
        // fmt.Println(string(card_json))
        var card Card
        err = json.Unmarshal(card_json, &card)
        if err != nil {
            fmt.Println(string(card_json))
        }
        check(err)

        fmt.Println(card.Name)
        for _, f := range(card.Fields) {
            value := f.Value
            if f.Sensitive != 0 {
                value = "*****"
            }

            fmt.Printf("\t%s (%s): %s\n", f.Label, f.Type, value)
        }
        fmt.Println("\tNote: ", card.Note)
    }

    err = rows.Err()
    check(err)
    rows.Close()
}

func main() {
    if len(os.Args) <= 1 {
        fmt.Println("filename required")
        return
    }

    db := openDb(os.Args[1])
    defer db.Close()

    iv, key := getCryptoParams(db)

    getCards(db, iv, key)
}
