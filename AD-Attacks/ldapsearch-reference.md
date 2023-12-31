## LDAP Search Reference Guide
```
# Basic Search (Anonymous)
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" "(objectclass=*)"

# Search with credentials
ldapsearch -x -D "cn=admin,dc=example,dc=com" -w <password> -h <hostname> -p <port> -b "dc=example,dc=com" "(objectclass=*)"

# Search with SSL/TLS
ldapsearch -Z -D "cn=admin,dc=example,dc=com" -w <password> -h <hostname> -p <port> -b "dc=example,dc=com" "(objectclass=*)"

# Filter results by attribute (e.g., cn)
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" "(cn=username)"

# Filter results by multiple attributes (e.g., cn and mail)
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" "(&(cn=username)(mail=email@example.com))"

# Return specific attributes
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" "(objectclass=*)" cn mail

# Search in subtree
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" -s sub "(objectclass=*)"

# Search in one level
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" -s one "(objectclass=*)"

# Search in base object only
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" -s base "(objectclass=*)"

# Search with size and time limits
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" -l <time_limit> -z <size_limit> "(objectclass=*)"

# Paging results
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" -E "pr=<page_size>/noprompt" "(objectclass=*)"

# Extended options with -o
ldapsearch -x -h <hostname> -p <port> -b "dc=example,dc=com" -o ldif-wrap=no "(objectclass=*)"
```
