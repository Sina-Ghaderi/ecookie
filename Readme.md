# ecookie
sign, encrypt and authenticate cookies with golang...   
this package uses rabbit cipher to encrypt and blake2 hash function in order to authenticate cookies.

why ecookies are special? 
- client cannot read content of the cookie
- client cannot change or modify content of the cookie.

### ecookie process flow
ecookie package process flow --> 
[](encrypt.jpg)
