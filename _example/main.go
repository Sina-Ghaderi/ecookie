package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"snix.ir/ecookie"
)

type te struct {
	IMMMMM      int       `json:"i"`
	DMMMMM      int       `json:"d"`
	Expire      time.Time `json:"expire"`
	SuperSecret string    `json:"secret"`
}

var key = []byte{
	0x11, 0x12, 0x13, 0x14,
	0x11, 0x12, 0x13, 0x14,
	0x11, 0x12, 0x13, 0x14,
	0x11, 0x12, 0x13, 0x14,
}

func main() {
	http.HandleFunc("/set", setHand)
	http.HandleFunc("/get", getHand)
	err := http.ListenAndServe(":8080", nil)
	log.Fatal(err)
}

func setHand(w http.ResponseWriter, r *http.Request) {
	x := new(te)
	x.DMMMMM = 10000
	x.IMMMMM = 90000
	x.Expire = time.Now().Add(time.Hour)
	x.SuperSecret = "some super secret data.. "

	d, err := json.Marshal(x)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	cc, err := ecookie.NewEncryptor(key)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	ec, err := cc.Encrypt(d)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:  "auth",
		Value: string(ec),
	})

	w.WriteHeader(http.StatusOK)
	w.Write(ec)
}

func getHand(w http.ResponseWriter, r *http.Request) {
	x, err := r.Cookie("auth")
	if err != nil {
		fmt.Println(err)
		return
	}

	ee, err := ecookie.NewDecryptor(key)
	if err != nil {
		fmt.Println(err)
		return
	}

	ll, err := ee.Decrypt([]byte(x.Value))
	if err != nil {
		fmt.Println(err)
		return
	}

	vv := new(te)
	err = json.Unmarshal(ll, vv)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(vv)
	fmt.Fprintf(w, "%+v", *vv)

}
