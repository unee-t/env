# Overview:

This repo facilitates the management of environment variables for a given Unee-T installation.

This is one of the dependency which is called when you deploy several of the Unee-T modules we need for a complete Unee-T installation.

# Pre-requisite:

In each of the environments that will need this code, the following AWS secrets MUST have been declared:
- DOMAIN
- STAGE
- BUGZILLA_DB_USER
- BUGZILLA_DB_PASSWORD

## Modules with `go.mod` files:

For the following modules, the dependancy is declared in the file `go.mod`:
- [apienroll](https://github.com/unee-t/apienroll)
- [unit](https://github.com/unee-t/unit)
- [lambda2sqs](https://github.com/unee-t/lambda2sqs)
- [invite](https://github.com/unee-t/invite)
- [rdslint](https://github.com/unee-t/rdslint)
- [inspectionreportgenerator](https://github.com/unee-t/inspectionreportgenerator)

## Other modules:

For the following modules the dependency is declared directly in the file `main.go`:
- [email.sms](https://github.com/unee-t/email2sms)
- [lambdaprince](https://github.com/unee-t/lambdaprince)
- [ses2case](https://github.com/unee-t/ses2case)

# Deployment:

- Tag release this repo with a version number [version]

## Option 1 - Update go.mod file
- In the codebase for the relevant Unee-T module, update the relevant line in file `go.mod` to the new [version] number :
Example:
```
import (
	...
	github.com/unee-t-ins/env [version]
	...
)
```

- Deploy the updated code for the relevant Unee-T module (this is usually done via a tag release of the code in the repo for that code).

## Option 2 - Update main.mod file

- In the codebase for the relevant Unee-T module, update the relevant line in file `main.mod` to the new [version] number :
Example:
```
require (
	...
	github.com/unee-t-ins/env [version]
	...
)
```

- Deploy the updated code for the relevant Unee-T module (this is usually done via a tag release of the code in the repo for that code).
