# LDAP-OSNAME-CHANGE-ALLOWER

This PHP script allows SELF user to read and write the 'Operating System' property on the target computer/s.

<p align="center"><img src="https://media4.giphy.com/media/3oz8xA07HKwLlpPUkM/giphy.gif?cid=ecf05e47fotex7dfxn6dprao1s9j7mqjkah9axkgn68gi4q2&rid=giphy.gif&ct=g"/></p>

## How was it developed?

Firstly, differences that occur on SDDL string has to be detected when Read & Write permissions added to Operating System Property on the target computer object.

At this stage, I used Chad Sikorra's amazing PHP [ldaptools](https://github.com/ChadSikorra/ldaptools) library for parsing SDDL string and much more.

As a result, we found that *two objects* need to be added -to the SELF- for Operating System's permissions to be granted:

<p align="center"><img src="https://user-images.githubusercontent.com/57866851/146933896-690428e2-5e6b-433e-94a7-9d0cbe34ca9d.png"/></p>

---

**sid: S-1-5-10** indicates that we are dealing with **SELF**:
<p align="center"><img src="https://user-images.githubusercontent.com/57866851/146934302-a734b19c-bbb3-4df3-8356-d97c95268ffd.png"/></p>


**objectType: 3e978925-8c01-11d0-afda-00c04fd930c9** indicates that we are changing **Operating System** attribute:
<p align="center"><img width=800 height=400 src="https://user-images.githubusercontent.com/57866851/146934700-73f71a95-b9b3-448d-99ee-3e65e37335e7.png"/></p>


## How to use?

os_read_allower has 6 parameters:

- **b** (Required): Base DN. Example: yeni.lab
- **i** (Required): IPv4 address of the target DC. Example: 10.154.127.75
- **u** (Required): Username for the LDAP connection. Example: Administrator
- **p** (Required): Password for the LDAP connection. Example: Passw0rd
- **d** (Optional): Specify a DN if you need to narrow the scope. Example: "ou=ankara,dc=yeni,dc=lab"
- **f** (Optional): Specify a filter if you need to be more specific. Example: "(cn=warsaw)"

---

#### Usage examples:

1. Specify a target OU or object. It gives the permission to all computers under that OU:

```bash
php os_read_allower.php -b yeni.lab -u administrator -p Passw0rd -d "OU=adana,dc=yeni,dc=lab" -i "10.154.127.75"
```

2. Don't specify any additional OU or object. It gives the permisson to all computers under the whole DN (ex: yeni.lab):

```bash
php os_read_allower.php -b yeni.lab -u administrator -p Passw0rd -i "10.154.127.75"
```

3. Use additional filter:
```bash
php os_read_allower.php -b yeni.lab -u administrator -p Passw0rd -d "OU=adana,dc=yeni,dc=lab" -i "10.154.127.75" -f "(cn=adanali)"
```

## For future changes:

os_read_allower should be a one-time operation. If you want to apply these changes for future computer objects; [default](https://github.com/oz9un/LDAP-OSNAME-CHANGE-ALLOWER/blob/main/DEFAULT_COMPUTER_OBJECT_SECURITY_DESCRIPTOR) security descriptor for computer object should be changed with the [modified](https://github.com/oz9un/LDAP-OSNAME-CHANGE-ALLOWER/blob/main/OS_PERM_COMPUTER_OBJECT_SECURITY_DESCRIPTOR).
