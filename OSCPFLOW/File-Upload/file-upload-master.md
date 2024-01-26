## Bypassing File Upload Restrictions
```
1. Create a malicious file with an extension that is accepted by the application.
2. Upload that file and click on send.
3. Capture the request in any proxy tool, edit the file extension to the malicious extension that you want. In some cases, you might need to change the content type of a file.
4. Forward the request to the server.

Suppose you have a limitation that you can only upload in a few formats like PDF, JPEG, JPG, ….But what if you can upload a PHP file by defying the Upload mechnism and validation of file type check. 

How does Bypass work
Well it depends on which kind of validation the system is using …it is just verfying the extension ? if its just doing that then it becomes very easy to bypass and upload a PHP file or something malicious.
Suppose we have to upload a JPG file so the extension must be something.jpg

Bypassing Normal extension
Now what we can do is we can upload a file which looks like this something.php.jpg or somethings.jpg.php.
```

## 2. Bypassing Magic Byte validation.
```
Magic Bytes
Successfully use magic bytes to fool the upload function into thinking php-reverse-shell.php was .pdf:
hexeditor -b php-reverse-shell.php   <--- Ended up putting in  25 50 44 46 2D (PDF) 
https://en.wikipedia.org/wiki/List_of_file_signatures
I added an additional ..... (five) dots so the php payload does not get affected by inserting 25 50 44 46 2D via hexeditor -b, dont forget the -b 
.....<?php
/backend/default/uploads/php-reverse-shell.php <----Had to go back and fuzz to find trigger url. /uploads/php-reverse-shell.php
```

```
Polyglots
For this method we use polygots. Polyglots, in a security context, are files that are a valid form of multiple different file types. For example, a GIFAR is both a GIF and a RAR file. There are also files out there that can be both GIF and JS, both PPT and JS, etc.

so while we have to upload a JPEG file type we actaully can upload a PHAR-JPEG file which will appear to be a JPEg file type to the server while validating. the reason is the file PHAR-JPEg file has both the JPEG header and the PHP file also. so while uploading it didn’t get detected and later after processing the PHP file can be used to exploit.

And at last Uploading a shell to some random websites for fun is not really cool so don’t ever try untill unless you have the permission to test.
```

**Test PDF upload functionality.**
- [https://github.com/jonaslejon/malicious-pdf](https://github.com/jonaslejon/malicious-pdf)
