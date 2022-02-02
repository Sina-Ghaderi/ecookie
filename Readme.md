# ecookie
sign, encrypt and authenticate cookies with golang...   
this package uses rabbit cipher to encrypt and blake2 hash function in order to authenticate cookies.

why ecookies are special? 
- client cannot read content of the cookie
- client cannot change or modify content of the cookie.

### usage and example
checkout [example](_example/) folder... simple http server that uses ecookie package   

this package lives on [snix public git servers](https://git.snix.ir/), this one is just a mirror..  
use `go get snix.ir/ecookie` or `go get github.com/sina-ghaderi/ecookie` to use this packge.


### ecookie process flow
ecookie package process flow, this is how ecookie encrypt data and calculate MAC  

![Encrypt](encrypt.jpg)  
ecookie decrypting data and cookie auth 

![Decrypt](decrypt.jpg)  

### go test ecookie 
execute `go test -v` on project root directory to test this package.

feel free to email me sina@snix.ir if you want to contribute to this project

Copyright 2022 SNIX LLC sina@snix.ir This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License version 2 as published by the Free Software Foundation. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
