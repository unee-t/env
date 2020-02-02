# Overview:

This repo facilitates the management of environment variables for a given Unee-T installation.

This is one of the dependency which is called when you deploy several of the Unee-T modules we need for a complete Unee-T installation.

This will create the following functions:
- GetSecret: Get the value of an AWS Parameter from the paramater store based on the AWS variable name.
- New: 
- Bucket: Create the S3 Bucket we need for a given Unee-T service.
- SNS: Create the arn endpoint we need when we deploy Unee-T dependencies
- Udomain: Create the urls for each service we need for a given Unee-T environment based on the DOMAIN and STAGE (DEV, DEMO or PROD).
- BugzillaDSN: get the string needed to access the bugzilla database. This is based on the AWS variables 
  - MYSQL_HOST
  - MYSQL_PORT
  - BUGZILLA_DB_NAME
  - BUGZILLA_DB_USER
  - BUGZILLA_DB_PASSWORD
- Protect: Make sure all calls are protected with the API key for this installation using: curl -H 'Authorization: Bearer secret' style
- Towr: A workaround for gorilla/pat: https://stackoverflow.com/questions/50753049/

# Pre-requisite:

In each of the environments that will need this code, the following AWS secrets MUST have been declared:
- DOMAIN
- INSTALLATION_ID
- STAGE
- DEFAULT_REGION
- MYSQL_HOST
- MYSQL_PORT
- BUGZILLA_DB_NAME
- BUGZILLA_DB_USER
- BUGZILLA_DB_PASSWORD

## Unee-T modules which uses a `go.mod` files:

For the following repositories, the dependancy is declared in the file `go.mod`:
- [apienroll](https://github.com/unee-t/apienroll)
- [unit](https://github.com/unee-t/unit)
- [lambda2sqs](https://github.com/unee-t/lambda2sqs)
- [invite](https://github.com/unee-t/invite)
- [rdslint](https://github.com/unee-t/rdslint)
- [inspectionreportgenerator](https://github.com/unee-t/inspectionreportgenerator)

### Deployment:

- Tag release this repo with a version number **[version]**
- In each of the repositories that uses this codebase (see above), 
  - Update the go dependancy
    `go get -u`
    See [Using Go Modules](https://blog.golang.org/using-go-modules) for more information
  - Deploy the updated code (this is usually done via a tag release of the code in the repo for that code).

## Other Unee-T modules that uses this codebase:

For the following modules the dependency is declared directly in the file `main.go`:
- [email.sms](https://github.com/unee-t/email2sms)
- [lambdaprince](https://github.com/unee-t/lambdaprince)
- [ses2case](https://github.com/unee-t/ses2case)

### Deployment:

- Tag release this repo with a version number **[version]**
- In each of the repositories that uses this codebase (see above), 
  - update the relevant line in file `main.mod` to the new **[version]** number :
    Example:
    ```
    require (
    	...
	    github.com/unee-t-ins/env [version]
	    ...
    )
    ```
  - Deploy the updated code (this is usually done via a tag release of the code in the repo for that code).