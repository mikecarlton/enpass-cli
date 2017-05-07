/*
  Access Enpass from CLI
  https://www.enpass.io/

  Copyright 2017 Mike Carlton mike@carltons.us

  This software is not affiliated with, created by or supported by Enpass

  Released under terms of the MIT License:
    http://www.opensource.org/licenses/mit-license.php
*/

package main

import (
    "os"
    "os/exec"
    "runtime"
    "syscall"
    "flag"
    "fmt"
    "bytes"
    "strings"
    "encoding/json"
    "crypto/cipher"
    "crypto/aes"
    "crypto/sha256"
    "golang.org/x/crypto/pbkdf2"
    "golang.org/x/crypto/ssh/terminal"
    "database/sql"
    _ "github.com/xeodou/go-sqlcipher"
    "github.com/keybase/go-keychain"
)

func check(err error) {
    if err != nil {
        if err.Error() == "file is encrypted or is not a database" {
            err = fmt.Errorf(
                "Your password is incorrect or the file is not a database")
        }
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}

func max(x, y int) int {
    if x > y {
        return x
    }
    return y
}

const KC_SERVICE = "enpass-cli"
const KC_ACCOUNT = ""
const KC_LABEL = ""
const KC_GROUP = ""

// get password from keychain if possible, else get from user
func getPassword() (password string, entered bool) {
    if runtime.GOOS == "darwin" {
        // look in keychain
        password_bytes, _ := keychain.GetGenericPassword(KC_SERVICE,
                                            KC_ACCOUNT, KC_LABEL, KC_GROUP)
        if password_bytes != nil {
            password = string(password_bytes)
            return
        }
    }

    // else prompt and read from keyboard
    fmt.Fprint(os.Stderr, "Password: ")
    password_bytes, err := terminal.ReadPassword(syscall.Stdin)
    check(err)

    password = string(password_bytes)
    fmt.Println()
    entered = true

    return
}

// save for future if requested
func savePassword(password string) {
    if runtime.GOOS == "darwin" {
        item := keychain.NewGenericPassword(KC_SERVICE, KC_ACCOUNT, KC_LABEL,
                                            []byte(password), KC_GROUP)
        item.SetSynchronizable(keychain.SynchronizableNo)
        item.SetAccessible(keychain.AccessibleWhenUnlocked)
        err := keychain.AddItem(item)
        check(err)
    }

    return
}

// clear password from keychain
func clearPassword() {
    if runtime.GOOS == "darwin" {
        err := keychain.DeleteGenericPasswordItem(KC_SERVICE, KC_ACCOUNT)
        if err != keychain.ErrorItemNotFound {
            check(err)
        }
    }

    return
}

// return a key created via pkdbf SHA-256
func generateKey(hash, salt []byte) (key []byte) {
    key = pbkdf2.Key(hash, salt, 2, 32, sha256.New)

    return
}

// extract the key and iv for fields from Identity row
func getCryptoParams(db *sql.DB, ignore_version bool) (iv, key []byte) {
    var id, version, signature, sync_uuid string
    var hash, info []byte
    const VERSION = "5"
    const SIGNATURE = "WalletxDb"

    row := db.QueryRow("SELECT * FROM Identity")
    err := row.Scan(&id, &version, &signature, &sync_uuid, &hash, &info)
    check(err)

    if debug {
        fmt.Fprintf(os.Stderr,
            "Id: %v, version: %v, signature: %v, sync uuid %v, hash bytes: %d, info bytes: %d\n",
            id, version, signature, sync_uuid, len(hash), len(info))
        fmt.Println()
    }

    if (version != VERSION || signature != SIGNATURE) && !ignore_version {
        fmt.Fprintf(os.Stderr,
                    "Database version is '%s' and signature is '%s'\n",
                    version, signature)
        fmt.Fprintf(os.Stderr,
                "The program is designed for version '%s' and signature '%s'\n",
                VERSION, SIGNATURE)
        fmt.Fprintf(os.Stderr,
               "To execute in spite of the difference, please use '-ignore'\n")
        os.Exit(1)
    }

    iv = info[16:32]
    salt := info[32:48]
    key = generateKey(hash, salt)

    return
}

// open and return the db handle for the enpass db
func openDb(db_file string, password string) (db *sql.DB) {
    if verbose {
        fmt.Fprintf(os.Stderr, "Reading database file '%s'\n", db_file)
    }
    db, err := sql.Open("sqlite3", db_file)
    check(err)

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

// decrypt card data, returning json blob
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

// Enpass DB structures
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
    id int                  // from db
    uuid string
    title string
    subtitle string
    ctype string
    category string
    deleted int
    trashed int

    Fields []Field          // rest unmarshalled from data json
    Iconid int64
    Name string
    Note string
    Templatetype string
    Updatetime string       // really a date
    Uuid string
}

// exceptions from the standard mapping
var specialLabel = map[string]string {
      "pin": "PIN",
      "url": "URL",
      "cvc": "CVC",
      "card_cvc": "Card CVC",
      "card_pin": "Card PIN",
}

// return Label if present, else generated label (replace '_' and titleize)
func (field Field) label() (label string) {
    switch {
    case field.Label != "":
        label = field.Label
    case field.Type == "text" && field.Sensitive == 0:
        label = "Security question"
    case field.Type == "text" && field.Sensitive != 0:
        label = "Security answer"
    default:
        value, ok := specialLabel[field.Type]
        if ok {
            label = value
        } else {
            label = strings.Title(strings.Replace(field.Type, "_", " ", -1))
        }
    }

    return
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
func (card Card) firstFieldByType(typeName string) (value string, err error) {
    fields := card.fieldsByType(typeName)
    if len(fields) > 0 && fields[0].Value != "" {
        value = fields[0].Value
    } else {
        err = fmt.Errorf("Card has no fields of type '%s'", typeName)
    }

    return
}

// get user field of the card
// defined as the first password or the first email if there is no username
func (card Card) getUser() (name string, err error) {
    name, err = card.firstFieldByType("username")
    if err != nil {
        name, err = card.firstFieldByType("email")
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

type View int

const (
    SingleLineView View = iota
    CardView
    FullCardView
)

// display the card as requested
//      default is single line
func (card Card) display(view View, show_sensitive bool, include_deleted bool) {
    if view == SingleLineView {
        user, _ := card.getUser()
        url, _ := card.firstFieldByType("url")
        password := ""
        if show_sensitive {
            password, _ = card.firstFieldByType("password")
        }
        fmt.Printf("%s:  %s  %s  %s\n", card.Name, user, url, password)
        return
    }

    const noteLabel = "Note"
    const indent = 4

    fmt.Println(card.Name)

    width := 0
    type_width := 0
    for pass := 0; pass <= 1 ; pass++ {
        for _, f := range(card.Fields) {
            value := f.Value
            if f.Sensitive != 0 && !show_sensitive && value != "" {
                value = "*****"
            }

            if (value != "" || view > CardView) &&
                    (f.Isdeleted == 0 || include_deleted) {
                if pass == 0 {
                    width = max(width, len(f.label()))
                    type_width = max(type_width, len(f.Type))
                } else {
                    fmt.Printf("%*s: %s\n", width+indent, f.label(), value)
                }
            }
        }

        if view > CardView || card.Note != "" {
            if pass == 0 {
                width = max(width, len(noteLabel))
            } else {
                fmt.Printf("%*s: %s\n", width+indent, noteLabel, card.Note)
            }
        }
    }
}

// copy the password to the clipboard and restore old contents after delay
func (card Card) passwordToClipboard(delay int) (err error) {
    if runtime.GOOS != "darwin" {
        err = fmt.Errorf("Password copy is not supported on this platform")
        return
    }

    password, err := card.firstFieldByType("password")
    if err != nil {
        err = fmt.Errorf("Could not find any password to paste")
        return
    }

    // save the current clipboard
    cmd := exec.Command("pbpaste")
    var current_clipboard bytes.Buffer
    cmd.Stdout = &current_clipboard
    err = cmd.Run()
    if err != nil {
        err = fmt.Errorf("Unable to save the current clipboard: %s", err)
        return
    }

    // put the password on the clipboard
    cmd = exec.Command("pbcopy")
    cmd.Stdin = strings.NewReader(password)
    err = cmd.Run()
    if err != nil {
        err = fmt.Errorf("Unable to copy the password to the clipboard: %s",
                         err)
        return
    }

    cmd = exec.Command("/bin/sh", "-c", fmt.Sprintf("sleep %d ; pbcopy", delay))
    cmd.Stdin = strings.NewReader(current_clipboard.String())
    err = cmd.Start()
    if err != nil {
        err = fmt.Errorf("Unable to clear the password from clipboard: %s", err)
        return
    }

    return
}

func jsonPrettyPrint(in []byte) (string) {
    var out bytes.Buffer
    err := json.Indent(&out, in, "", "\t")
    if err != nil {
        return string(in)
    }
    return out.String()
}

func dumpCard(db *sql.DB, iv, key []byte, id int) {
    var (
            iconid, updatetime, deleted, trashed int
            title, subtitle, ctype, category, customiconid, uuid, urls,
                formfields string
            data []byte
    )

    row := db.QueryRow("SELECT * FROM Cards WHERE id = ?", id)
    err := row.Scan(&id, &title, &subtitle, &ctype, &category, &iconid,
                    &customiconid, &updatetime, &uuid, &data, &trashed,
                    &deleted, &urls, &formfields)
    check(err)

    fmt.Printf("id: %d, title: '%s', subtitle: '%s'\n", id, title, subtitle)
    fmt.Printf("    uuid: %s, deleted: %d, trashed: %d\n",
               uuid, deleted, trashed)
    fmt.Printf("    type: '%s', category: '%s', icon id: %d, custom icon id :'%s'\n",
               ctype, category, iconid, customiconid);
    fmt.Printf("    urls: '%s', formfields: '%s'\n", urls, formfields)

    card_json := decrypt(data, iv, key)
    fmt.Printf("    data: '%s'\n", jsonPrettyPrint(card_json))

    return
}

func getCards(db *sql.DB, iv, key []byte, include_deleted bool) (cards []Card) {
    query := "SELECT id, uuid, title, subtitle, deleted, " +
             "       trashed, type, category, data " +
             "FROM Cards"
    if !include_deleted {
        query += " WHERE deleted = 0 AND trashed = 0"
    }
    query += " ORDER BY title, trashed, deleted"

    rows, err := db.Query(query)
    check(err)
    defer rows.Close()

    for rows.Next() {
        var (
            id int
            uuid string
            title, subtitle string
            deleted, trashed int
            ctype, category string
            data []byte
        )

        err := rows.Scan(&id, &uuid, &title, &subtitle, &deleted, &trashed,
                         &ctype, &category, &data)
        check(err)

        card_json := decrypt(data, iv, key)

        var card Card
        err = json.Unmarshal(card_json, &card)
        if err != nil {
            fmt.Println(string(card_json))
        }
        check(err)

        card.id = id
        card.uuid = uuid
        card.title = title
        card.subtitle = subtitle
        card.ctype = ctype
        card.category = category
        card.deleted = deleted
        card.trashed = trashed

        if uuid != card.Uuid {
            fmt.Println("Warning: card title '%s' != name '%s'",
                        title, card.Name)
        }
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
var debug = false

func main() {
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr,
                      "Usage: %s [options] [-a | NAME [USERNAME | EMAIL]]\n",
                    os.Args[0])
        flag.PrintDefaults()
    }

    var db_file string
    var delay int
    var match_all, show_sensitive, no_copy_password, unlimited, include_deleted,
        save_to_keychain, clear_from_keychain, ignore_version bool
    var full_display, expanded_display bool

    flag.StringVar(&db_file, "file", "", "enpass db file")
    flag.BoolVar(&verbose, "v", false, "set verbose mode")
    flag.IntVar(&delay, "w", 30,
                "seconds before clearing password from clipboard")
    flag.BoolVar(&match_all, "a", false, "match all records (implies -u)")
    flag.BoolVar(&unlimited, "u", false, "show all matching records")
    flag.BoolVar(&save_to_keychain, "k", false,
                 "save master password to keychain")
    flag.BoolVar(&clear_from_keychain, "K", false,
                 "clear master password from keychain")
    flag.BoolVar(&full_display, "c", false, "show full cards")
    flag.BoolVar(&expanded_display, "C", false,
                 "show full cards, including blank fields")
    flag.BoolVar(&include_deleted, "d", false, "include deleted records")
    flag.BoolVar(&debug, "D", false, "set debug mode")
    flag.BoolVar(&show_sensitive, "s", false,
                 "show sensitive fields (including passwords)")
    flag.BoolVar(&no_copy_password, "n", false, "do not copy password")
    flag.BoolVar(&ignore_version, "ignore", false,
                 "run with unsupported database version")
    flag.Parse()

    var view View
    switch {
    case full_display: view = CardView
    case expanded_display: view = FullCardView
    default: view = SingleLineView
    }

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

    if clear_from_keychain {
        clearPassword()
    }
    password, password_entered := getPassword()
    db := openDb(db_file, password)
    defer db.Close()

    iv, key := getCryptoParams(db, ignore_version)

    cards := getCards(db, iv, key, include_deleted)
    num_matched := 0
    password_message := ""
    for _, card := range cards {
        match := match_all || strings.Contains(strings.ToLower(card.Name), name)
        if match && match_user {
            cardUser, err := card.getUser()
            match = err == nil &&
                    strings.Contains(strings.ToLower(cardUser), user)
        }

        if match {
            num_matched += 1
            if num_matched == 1 || unlimited || match_all {
                if num_matched > 1 && view > SingleLineView {
                    fmt.Println()
                }
                card.display(view, show_sensitive, include_deleted)
            }

            if debug {
                fmt.Println()
                dumpCard(db, iv, key, card.id)
            }

            if num_matched == 1 && !no_copy_password {
                err := card.passwordToClipboard(delay)
                if err != nil {
                    password_message = fmt.Sprintf("%v", err)
                } else {
                    password_message = fmt.Sprintf(
                        "Password copied to clipboard, clearing in %d seconds",
                                                   delay)
               }
            }
        }
    }

    if num_matched > 1 {
        fmt.Fprintf(os.Stderr, "Matched %d cards\n", num_matched)
    }

    if password_message != "" {
        fmt.Fprintf(os.Stderr, "\n%s\n", password_message)
    }

    // only save if requested and entered and no errors
    if save_to_keychain && password_entered {
        savePassword(password)
    }
}
