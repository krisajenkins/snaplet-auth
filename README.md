## Setting & Checking Passwords

Just use Crypto.BCrypt at a repl:

``` sh
$ stack gchi
> import Crypto.BCrypt
> let p = Data.ByteString.Char8.pack

> hashPasswordUsingPolicy slowerBcryptHashingPolicy (p "mypassword")
Just "$2y$14$xBBZdWgTa8fSU1aPFP5IxeVdUKfT7hUDjmusZEAiNBiYaYEGY/Sh6"

> validatePassword (p "$2y$14$xBBZdWgTa8fSU1aPFP5IxeVdUKfT7hUDjmusZEAiNBiYaYEGY/Sh6") (p "badpass")
True
```
