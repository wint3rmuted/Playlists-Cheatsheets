## Php unserialize() call
```
Serialization is basically converting a set of data structures or objects into a stream of bytes to transmit it to a memory, a database, or a file.
The main advantage is to save the state of an object to be able to recreate it whenever needed, eg. video games, etc.
This vulnerability could occur when user-supplied input is not appropriately sanitized before being passed to the unserialize() PHP function.
Since PHP allows object serialization, you can pass ad-hoc serialized strings to a vulnerable unserialize() call, resulting in an arbitrary PHP object(s) injection into the application scope.
```
## Conditions
```
Exploiting a PHP Object Injection vulnerability the following two conditions must be met:
    1. The application must have a class that implements a PHP magic method (such as __wakeup or __destruct) that can be used to carry out malicious attacks, or to start a “POP chain”.
    2. All of the classes used during the attack must be declared when the vulnerable unserialize() is being called, otherwise object autoloading must be supported for such classes.
