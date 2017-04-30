
/*
  Access Enpass from CLI

  Copyright 2017 Mike Carlton
  mike@carltons.us

  Released under terms of the MIT License:
    http://www.opensource.org/licenses/mit-license.php
*/

package main

import (
    "os"
    "runtime"
    "syscall"
    "flag"
    "fmt"
    "strings"
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

    return
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

    return
}

func openDb(db_file string) (db *sql.DB) {
    if verbose {
        fmt.Fprintf(os.Stderr, "Reading database file '%s'\n", db_file)
    }
    db, err := sql.Open("sqlite3", db_file)
    check(err)

    password, ok := os.LookupEnv("ENPASS_PASSWORD")
    if !ok {
        fmt.Fprint(os.Stderr, "Password: ")
        password_bytes, err := terminal.ReadPassword(syscall.Stdin)
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

    return
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

    return
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

// return field(s) of given type
func (card Card) fieldsByType(typeName string) (fields []Field) {
    typeName = strings.ToLower(typeName)
    for _, f := range card.Fields {
        if strings.ToLower(f.Type) == typeName {
            fields = append(fields, f)
        }
    }

    return
}

// return value of first non-empty field of given type
func (card Card) firstByType(typeName string) (value string, err error) {
    fields := card.fieldsByType(typeName)
    if len(fields) > 0 && fields[0].Value != "" {
        value = fields[0].Value
    } else {
        err = fmt.Errorf("Card has no fields of type '%s'", typeName)
    }

    return
}

func (card Card) getUser() (name string, err error) {
    name, err = card.firstByType("username")
    if err != nil {
        name, err = card.firstByType("email")
    }

    if err != nil {
        err = fmt.Errorf("Card has no username or email")
    }

    return
}

// return field(s) with type of given name
func (card Card) fieldsMatchByType(name, value string) (fields []Field) {
    name = strings.ToLower(name)
    value = strings.ToLower(value)
    for _, f := range card.Fields {
        if strings.ToLower(f.Type) == name &&
           strings.Contains(strings.ToLower(f.Value), value) {
            fields = append(fields, f)
        }
    }

    return
}

func (card Card) display(one_line, show_password bool) {
    if one_line {
        user, _ := card.getUser()
        url, _ := card.firstByType("url")
        password := ""
        if show_password {
            password, _ = card.firstByType("password")
        }
        fmt.Printf("%s: %s  %s  %s\n", card.Name, user, url, password)
    } else {
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
}

func getCards(db *sql.DB, iv, key []byte) (cards []Card) {
    rows, err := db.Query("SELECT title, subtitle, data " +
                           "FROM Cards " +
                           "WHERE deleted = 0 AND trashed = 0")
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

        if title != card.Name {
            fmt.Println("Warning: card title '%s' != name '%s'",
                        title, card.Name)
        }

        cards = append(cards, card)
    }

    err = rows.Err()
    check(err)
    rows.Close()

    return
}

var verbose = false

func main() {
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr,
                      "Usage: %s [options] [-a | NAME [USERNAME | EMAIL]]\n",
                    os.Args[0])
        flag.PrintDefaults()
    }

    var db_file string
    var match_all, one_line, show_password bool

    flag.StringVar(&db_file, "file", "", "enpass db file")
    flag.BoolVar(&verbose, "v", false, "set verbose mode")
    flag.BoolVar(&match_all, "a", false, "match all records")
    flag.BoolVar(&one_line, "o", false, "show records on one line")
    flag.BoolVar(&show_password, "p", false, "show passwords")
    flag.Parse()

    if db_file == "" {
        db_file = os.Getenv("ENPASS_DB_FILE")
    }

    if db_file == "" {
        if runtime.GOOS == "darwin" {
            home, ok := os.LookupEnv("HOME")
            if ok {
                db_file = home + "/Documents/Enpass/walletx.db"
            }
        }
    }

    if db_file == "" {
        fmt.Println("filename required")
        return
    }

    if match_all && flag.NArg() != 0 ||
       !match_all && (flag.NArg() < 1 || flag.NArg() > 2) {
        flag.Usage()
        return
    }

    name := strings.ToLower(flag.Arg(0))
    match_user := flag.NArg() == 2
    user := strings.ToLower(flag.Arg(1))

    db := openDb(db_file)
    defer db.Close()

    iv, key := getCryptoParams(db)

    cards := getCards(db, iv, key)
    for _, card := range cards {
        match := match_all || strings.Contains(strings.ToLower(card.Name), name)
        if match && match_user {
            cardUser, err := card.getUser()
            match = err == nil &&
                        strings.Contains(strings.ToLower(cardUser), user)
        }

        if match {
            card.display(one_line, show_password)
        }
    }
}
