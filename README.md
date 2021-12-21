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
<p align="center"><img src="https://user-images.githubusercontent.com/57866851/146934700-73f71a95-b9b3-448d-99ee-3e65e37335e7.png"/></p>


## How to use?

os_read_allower has two main usage:

1. Specify a target OU or object. It gives the permission to all computers under that OU.

```bash
php os_read_allower.php -b yeni.lab -u administrator -p Passw0rd -f "OU=ldaporg1,dc=yeni,dc=lab"
```

2. Don't specify any additional OU or object. It gives the permisson to all computers under the whole DN (ex: yeni.lab).

```bash
php os_read_allower.php -b yeni.lab -u administrator -p Passw0rd
```
