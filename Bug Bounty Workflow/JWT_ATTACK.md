# JWT Attack

### FIRST IF YOU DON'T KNOW WHAT IS JWT YOU MUST READ AND WATCH BELOW RESOURCES
-----------------------------------------------------------------------
* https://twitter.com/BHinfoSecurity/status/1299743624553549825?s=09
* https://youtu.be/ghfmx4pr1Qg ( very begginer friendly)
* https://medium.com/ag-grid/a-plain-english-introduction-to-json-web-tokens-jwt-what-it-is-and-what-it-isnt-8076ca679843
* https://medium.com/swlh/hacking-json-web-tokens-jwts-9122efe91e4a
* https://anubhav-singh.medium.com/get-a-feel-of-jwt-json-web-token-8ee9c16ce5ce
* https://anubhav-singh.medium.com/attacks-on-json-web-token-jwt-278a49a1ad2e
* Cheat Sheet - [Pentester's Lab](https://assets.pentesterlab.com/jwt_security_cheatsheet/jwt_security_cheatsheet.pdf)
 
### NOTES FOR ATTACKING JWT
* What the heck is this ?!
```
1. It is an authentication type 
2. It consists of header,payload,Signature
```
---------------------------------------------------------------------------------
* Header 	
```
{
 "alg" : "HS256",
 "typ" : "JWT"
}
```
-------------------------------------------------------------------
* Payload 	
```
{
 "loggedInAs" : "admin",
 "iat" : 1422779638
}
```
-----------------------------------------------------------------------------
* Signature 	
```
HMAC-SHA256
(
 secret,
 base64urlEncoding(header) + '.' +
 base64urlEncoding(payload)
)
```
-----------------------------------------------
* Changing alg to null 
* Example
```
{
 "alg" : "NONE",
 "typ" : "JWT"
}
Note;;////--remove the signuature
You can also use none,nOne,None,n0Ne
```
-------------
* Change the payload like 
```
Payload 	

{
 "loggedInAs" : "admin", 
 "iat" : 1422779638
}
```
* Here change user to admin
----------------------------------------------------
 # SOME MORE TIPS AND METHOD
 --------------------------------------------------------
 1. First decode full token or 1 1 each part of token to base64
 2. Change the payload use jwt web token burp
 3. Changing encrption  RS256 to HS256
 4. Signature not changes remove it or temper it,
 5. Brute forcing the key in hs256 because it use same key to sign and verify means publickey=private key
 ---------------------------------------------------------------------------------------------------
 ### Other Easy Method
```
1) Create a account
2) Inspect the token
3) Base64 decode the header
4) If any Kid= parameter are there so you can find some bugs
5) Using that parameter you can also find directory traversal , i tell you how
6) Change that kid= parameter with you directory traversal payload
7) Change payload {"user":"admin"}
8) Create a python script that generate a exploit token. (If you want that script so dm me in Twitter )
9) Put that token and reload the page
10) Done
```
---
 # TOOLS TO USE
 -----------------------------------------------------------------------------------------------
 * [Jwt token attack burp extention](https://github.com/portswigger/json-web-token-attacker)
 * Base64 decoder
 * jwt.io to analyse the struct of token
 * jwt cat for weak secret token [jwtcat](https://github.com/aress31/jwtcat) 
 * Tool is used for validating, forging, scanning and tampering JWTs [jwt_tool](https://github.com/ticarpi/jwt_tool)
 * Tool to test security of JSON Web Tokens [jwtXploiter](https://github.com/DontPanicO/jwtXploiter)

---------------------------------------------------------------------------------------------------------------------------
### SOURCES: 
- Intresting blog - [Medium](https://barrymalone.medium.com/json-web-tokens-beginner-exploitation-5a44f8f6efff)
* Youtube,Medium,Github,Google
### Author
* [Naman Shah](https://twitter.com/naman_1910)
* [@kAshhadali10](https://twitter.com/kAshhadali10)
* [@0xrtt](https://twitter.com/0xrtt)
* [Anubhav Singh](https://twitter.com/AnubhavSingh_)
