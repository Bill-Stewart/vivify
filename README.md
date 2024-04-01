# vivify

**vivify** is a Windows console (text-based, command-line) program that keeps an account active by securely resetting its password to a random password and optionally performing a logon with the account.

## BACKGROUND

Many domain administrators perform cleanup tasks that remove inactive accounts based on last password change and/or logon timestamps. Some applications may require domain accounts that don't log onto the domain but but still need to remain enabled. **vivify** is useful to keep these kinds of accounts active.

## DISCLAIMER

> CAUTION! This program resets the password of an acccount to a random password that is immediately cleared from memory. It is not possible to recover the random password set on the account, so **do not use this program on an account that an application uses to authenticate** (for example, to run a service or a scheduled task): This will break the application the next time it uses the acount to authenticate! You have been warned. The author of this program is not responsible for broken applications as a result of this misuse of this program (accidental or otherwise).

## AUTHOR

Bill Stewart - bstewart at iname dot com

## LICENSE

**vivify** is covered by the GNU Public License (GPL). See the file `LICENSE` for details.

## USAGE

Command-line parameters, except for the account name, are case-sensitive.

`vivify` _accountname_ [`--domainname` _name_ | `--localaccount`] [`--passwordlength` _length_] [`--logon` [`--delay` _delay_]] [`--noprompt`] [`--quiet`]

## PARAMETERS

_accountname_ - Specifies the account username - do not include a domain or computer name as a part of the username

`--domainname` - Specifies the domain name where the account exists

`--localaccount` - Specifies that the account is local (i.e., an account that exists only on the current computer)

`--passwordlength` - Specifies random password length (0 to 256 characters)

`--logon` - Attempts a logon using the account

`--delay` - Waits at least this number of milliseconds after the password change before attempting a logon (0 to 14400000 milliseconds)

`--noprompt` - Do not prompt for confirmation

`--quiet` - Suppresses output and error messages

## REMARKS

The default random password length is 127 characters.

When using `--logon`, the default delay is 1000 millisconds (1 second); depending on the domain, a longer delay might be needed to account for Active Directory replication.

If the current computer is a domain member, the default value for `--domainname` is the current computer's domain; otherwise, the account is assumed to be a local account (i.e., `--localaccount`).

The `--domainname` parameter does not work if the current computer is not a domain member (i.e., the account name must specify a local account).

The account running the program must have permission to reset the password for the named account.

The `--logon` parameter uses the [**LogonUserW**](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw) Windows API function to perform a "network logon" for the account on the current computer.

## EXIT CODE

The exit code will be 0 if the command completed successfully, or non-zero if an error occurred.
