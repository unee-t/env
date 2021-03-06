package env

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/prometheus/client_golang/prometheus"
	
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

var pingPollingFreq = 5 * time.Second

// Important GOTCHA
// See https://stackoverflow.com/questions/24487943/invoking-struct-function-gives-cannot-refer-to-unexported-field-or-method
// An identifier may be exported to permit access to it from another package. An identifier is exported if both:
// - the first character of the identifier's name is a Unicode upper case letter (Unicode class "Lu"); and
// - the identifier is declared in the package block or it is a field name or method name.

// We need this so it can be exported
type EnvironmentId int

//HandlerSqlConnexion is a type of variable to help us manage our connexion to the SQL databases
type HandlerSqlConnexion struct {
	DSN            string // aurora database connection string
	APIAccessToken string
	db             *sql.DB
	environmentId  EnvironmentId
}

// Environment is a type of variable to help us manage our differing {dev,demo,prod} AWS accounts
type Environment struct {
	environmentId   EnvironmentId
	Cfg       		aws.Config
	AccountID 		string
	Stage     		string
}

// https://github.com/unee-t/processInvitations/blob/master/sql/1_process_one_invitation_all_scenario_v3.0.sql#L12-L16
const (
	EnvUnknown EnvironmentId = iota 	// Oops
	EnvDev								// Development aka Staging
	EnvProd								// Production
	EnvDemo								// Demo, which is like Production, for prospective customers to try
)

// GetSecret is the Golang equivalent for
// aws --profile your-aws-cli-profile ssm get-parameters --names API_ACCESS_TOKEN --with-decryption --query Parameters[0].Value --output text

func (thisEnvironment Environment) GetSecret(key string) string {

	val, ok := os.LookupEnv(key)
	if ok {
		log.Warnf("GetSecret Warning: No need to query AWS parameter store: %s overridden by local env", key)
		return val
	}
	// Ideally environment above is set to avoid costly ssm (parameter store) lookups

	ps := ssm.New(thisEnvironment.Cfg)
	in := &ssm.GetParameterInput{
		Name:           aws.String(key),
		WithDecryption: aws.Bool(true),
	}
	req := ps.GetParameterRequest(in)
	out, err := req.Send(context.TODO())
	if err != nil {
		log.WithError(err).Errorf("GetSecret Error: failed to retrieve credentials for looking up %s", key)
		return ""
	}
	return aws.StringValue(out.Parameter.Value)
}

// NewConfig setups the configuration assuming various parameters have been setup in the AWS account
// - DEFAULT_REGION
// - STAGE
func NewConfig(cfg aws.Config) (thisEnvironment Environment, err error) {

	// Save for ssm
		thisEnvironment.Cfg = cfg

		svc := sts.New(cfg)
		input := &sts.GetCallerIdentityInput{}
		req := svc.GetCallerIdentityRequest(input)
		result, err := req.Send(context.TODO())
		if err != nil {
			return thisEnvironment, err
		}

	// We get the ID of the AWS account we use
		thisEnvironment.AccountID = aws.StringValue(result.Account)
		log.Infof("NewConfig Log: The AWS Account ID for this environment is: %s", thisEnvironment.AccountID)

	// We get the value for the DEFAULT_REGION
		var defaultRegion string
		valdefaultRegion, ok := os.LookupEnv("DEFAULT_REGION")
		if ok {
			defaultRegion = valdefaultRegion
			log.Infof("NewConfig Log: DEFAULT_REGION was overridden by local env: %s", valdefaultRegion)
		} else {
			defaultRegion = thisEnvironment.GetSecret("DEFAULT_REGION")
			log.Infof("NewConfig Log: We get the DEFAULT_REGION from the AWS parameter store")
		}
	
		if defaultRegion == "" {
			log.Fatal("NewConfig fatal: DEFAULT_REGION is unset, this is a fatal problem")
		}

		cfg.Region = defaultRegion
		log.Infof("NewConfig Log: The AWS region for this environment has been set to: %s", cfg.Region)

	// We get the value for the STAGE
		var stage string
		valstage, ok := os.LookupEnv("STAGE")
		if ok {
			stage = valstage
			log.Infof("NewConfig Log: STAGE was overridden by local env: %s", valstage)
		} else {
			stage = thisEnvironment.GetSecret("STAGE")
			log.Infof("NewConfig Log:  We get the STAGE from the AWS parameter store")
		}
	
		if stage == "" {
			log.Fatal("NewConfig fatal: STAGE is unset, this is a fatal problem")
		}

		thisEnvironment.Stage = stage

	// Based on the value of the STAGE variable we do different things
		switch thisEnvironment.Stage {
		case "dev":
			thisEnvironment.environmentId = EnvDev
			return thisEnvironment, nil
		case "prod":
			thisEnvironment.environmentId = EnvProd
			return thisEnvironment, nil
		case "demo":
			thisEnvironment.environmentId = EnvDemo
			return thisEnvironment, nil
		default:
			log.WithField("stage", thisEnvironment.Stage).Error("NewConfig Error: unknown stage")
			return thisEnvironment, nil
		}
}

func (thisEnvironment Environment) BugzillaDSN() string {

	// Get the value of the variable BUGZILLA_DB_USER
		var bugzillaDbUser string
		valbugzillaDbUser, ok := os.LookupEnv("BUGZILLA_DB_USER")
		if ok {
			bugzillaDbUser = valbugzillaDbUser
			log.Infof("BugzillaDSN Log: BUGZILLA_DB_USER was overridden by local env: %s", valbugzillaDbUser)
		} else {
			bugzillaDbUser = thisEnvironment.GetSecret("BUGZILLA_DB_USER")
			log.Infof("BugzillaDSN Log: We get the BUGZILLA_DB_USER from the AWS parameter store")
		}

		if bugzillaDbUser == "" {
			log.Fatal("BugzillaDSN Fatal: BUGZILLA_DB_USER is unset, this is a fatal problem")
		}

	// Get the value of the variable 
		var bugzillaDbPassword string
		valbugzillaDbPassword, ok := os.LookupEnv("BUGZILLA_DB_PASSWORD")
		if ok {
			bugzillaDbPassword = valbugzillaDbPassword
			log.Infof("BugzillaDSN Log: BUGZILLA_DB_PASSWORD was overridden by local env: **hidden_secret**")
		} else {
			bugzillaDbPassword = thisEnvironment.GetSecret("BUGZILLA_DB_PASSWORD")
			log.Infof("BugzillaDSN Log: We get the BUGZILLA_DB_PASSWORD from the AWS parameter store")
		}

		if bugzillaDbPassword == "" {
			log.Fatal("BugzillaDSN Fatal: BUGZILLA_DB_PASSWORD is unset, this is a fatal problem")
		}

	// Get the value of the variable 
		var mysqlhost string
		valmysqlhost, ok := os.LookupEnv("MYSQL_HOST")
		if ok {
			mysqlhost = valmysqlhost
			log.Infof("BugzillaDSN Log: MYSQL_HOST was overridden by local env: %s", valmysqlhost)
		} else {
			mysqlhost = thisEnvironment.GetSecret("MYSQL_HOST")
			log.Infof("BugzillaDSN Log: We get the MYSQL_HOST from the AWS parameter store")
		}

		if mysqlhost == "" {
			log.Fatal("BugzillaDSN Fatal: MYSQL_HOST is unset, this is a fatal problem")
		}

	// Get the value of the variable 
		var mysqlport string
		valmysqlport, ok := os.LookupEnv("MYSQL_PORT")
		if ok {
			mysqlport = valmysqlport
			log.Infof("BugzillaDSN Log: MYSQL_PORT was overridden by local env: %s", valmysqlport)
		} else {
			mysqlport = thisEnvironment.GetSecret("MYSQL_PORT")
			log.Infof("BugzillaDSN Log: We get the MYSQL_PORT from the AWS parameter store")
		}

		if mysqlport == "" {
			log.Fatal("BugzillaDSN Fatal: MYSQL_PORT is unset, this is a fatal problem")
		}

	// Get the value of the variable 
		var bugzillaDbName string
		valbugzillaDbName, ok := os.LookupEnv("BUGZILLA_DB_NAME")
		if ok {
			bugzillaDbName = valbugzillaDbName
			log.Infof("BugzillaDSN Log: BUGZILLA_DB_NAME was overridden by local env: %s", valbugzillaDbName)
		} else {
			bugzillaDbName = thisEnvironment.GetSecret("BUGZILLA_DB_NAME")
			log.Infof("BugzillaDSN Log: We get the BUGZILLA_DB_NAME from the AWS parameter store")
		}

		if bugzillaDbName == "" {
			log.Fatal("BugzillaDSN Fatal: BUGZILLA_DB_NAME is unset, this is a fatal problem")
		}

	// Build the string that will allow connection to the BZ database
		return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?multiStatements=true&sql_mode=TRADITIONAL&timeout=15s&collation=utf8mb4_unicode_520_ci",
			bugzillaDbUser,
			bugzillaDbPassword,
			mysqlhost,
			mysqlport,
			bugzillaDbName)
}

// NewDbConnexion setups what we need to access the DB assuming various parameters have been setup in the AWS account

func NewDbConnexion() (bzDbConnexion HandlerSqlConnexion, err error) {

	// We get the AWS configuration information for the default profile
		cfg, err := external.LoadDefaultAWSConfig()
		if err != nil {
			log.WithError(err).Fatal("NewDbConnexion Fatal: We do not have the AWS credentials we need")
			return
		}

	// We declare the environment we are in
		thisEnvironment, err := NewConfig(cfg)
		if err != nil {
			log.WithError(err).Warn("NewDbConnexion Warning: error getting some of the parameters for that environment")
		} else {
			log.Infof("NewDbConnexion Log: This is the environment: %s", thisEnvironment.environmentId)
		}

	// cfg also needs the default region.
	// We get the value for the DEFAULT_REGION
		defaultRegion, ok := os.LookupEnv("DEFAULT_REGION")
		if ok {
			log.Infof("NewDbConnexion Log: DEFAULT_REGION was overridden by local env: %s", defaultRegion)
		} else {
			defaultRegion = thisEnvironment.GetSecret("DEFAULT_REGION")
			log.Infof("NewDbConnexion Log: We get the DEFAULT_REGION from the AWS parameter store")
		}
	
		if defaultRegion == "" {
			log.Fatal("NewConfig fatal: DEFAULT_REGION is unset, this is a fatal problem")
		}
		
		// Set the AWS Region that the service clients should use
			cfg.Region = defaultRegion
			log.Infof("NewDbConnexion Log: The AWS region for this environment has been set to: %s", cfg.Region)

	// We get the value for the API_ACCESS_TOKEN
		apiAccessToken, ok := os.LookupEnv("API_ACCESS_TOKEN")
		if ok {
			log.Infof("NewDbConnexion Log: API_ACCESS_TOKEN was overridden by local env: **hidden secret**")
		} else {
			apiAccessToken = thisEnvironment.GetSecret("API_ACCESS_TOKEN")
			log.Infof("NewDbConnexion Log: We get the API_ACCESS_TOKEN from the AWS parameter store")
		}
	
		if apiAccessToken == "" {
			log.Fatal("NewConfig fatal: API_ACCESS_TOKEN is unset, this is a fatal problem")
		}

	// We have everything --> We create the database connexion string
		bzDbConnexion = HandlerSqlConnexion{
			DSN:            thisEnvironment.BugzillaDSN(), // `BugzillaDSN` is a function that is defined in the uneet/env/main.go dependency.
			APIAccessToken: apiAccessToken,
			environmentId:  thisEnvironment.environmentId,
		}
	
	// Test if this is working as it should
		bzDbConnexion.db, err = sql.Open("mysql", bzDbConnexion.DSN)
		if err != nil {
			log.WithError(err).Fatal("NewDbConnexion fatal: error opening database")
			return
		} else {
			log.Infof("NewDbConnexion Log: We can access the database")
		}

	microservicecheck := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "microservice",
			Help: "Version with DB ping check",
		},
		[]string{
			"commit",
		},
	)

	// What is the version of this commit
		version := os.Getenv("UP_COMMIT")

	go func() {
		for {
			if bzDbConnexion.db.Ping() == nil {
				microservicecheck.WithLabelValues(version).Set(1)
				log.Infof("NewDbConnexion Log: Ping of the DB exited with 1")
			} else {
				microservicecheck.WithLabelValues(version).Set(0)				
				log.Infof("NewDbConnexion Log: Ping of the DB exited with 0")
			}
			time.Sleep(pingPollingFreq)
		}
	}()

	err = prometheus.Register(microservicecheck)
	if err != nil {
		log.Warn("NewDbConnexion Warning: prom already registered")
	} else {
		log.Infof("NewDbConnexion Log: prometheus registration is OK")
	}
	return
}

// Protect using: curl -H 'Authorization: Bearer secret' style
// Modelled after https://github.com/apex/up-examples/blob/master/oss/golang-basic-auth/main.go#L16
func Protect(currentBzConnexion http.Handler, APIAccessToken string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string
		// Get token from the Authorization header
		// format: Authorization: Bearer
		// This token is coming from the `frontend` (the MEFE)
		// IF YOU HAVE CHANGED THE API_ACCESS_TOKEN THEN YOU MUST REDEPLOY ALL THE CODEBASE:
		//	- frontend
		//	- apienroll
		//	- unit
		//	- invite
		//	- lambda2sqs
		//	- etc...
		tokens, ok := r.Header["Authorization"]
		if ok && len(tokens) >= 1 {
			token = tokens[0]
			token = strings.TrimPrefix(token, "Bearer ")
		}

		// Check if the token is empty
		if token == "" {
			log.Errorf("Protect Error: The Token on the http request is empty")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		// Check if this is the correct API Access token
		}else if token != APIAccessToken {
			log.Errorf("Protect Error: The Token on the request (%q) is different from the APIAccessToken (**hidden secret**) that we have configured", token)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		currentBzConnexion.ServeHTTP(w, r)
	})
}

// Towr is a workaround for gorilla/pat: https://stackoverflow.com/questions/50753049/
// Wish I could make this simpler
func Towr(currentBzConnexion http.Handler) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) { 
		currentBzConnexion.ServeHTTP(w, r) 
	}
}

func (thisEnvironment Environment) Bucket(svc string) string {

	// Most common bucket
		if svc == "" {
			svc = "media"
		}

	// We establish the ID of the Installation based on parameters INSTALLATION_ID
	// This variable can be edited in the AWS parameter store
		installationID := thisEnvironment.GetSecret("INSTALLATION_ID")
		log.Infof("Bucket Log: We have a value for INSTALLATION_ID in the AWS parameter store: %s", installationID)

	// If we have no installation ID we stop
		if installationID == "" {
			log.Fatal("Bucket fatal: installationID is unset, this is a fatal problem")
		}

	// To preserve legacy in case this is the Public Unee-T installation
		if installationID == "main" {
			// Preserve original bucket names
			return fmt.Sprintf("%s-%s-unee-t", thisEnvironment.Stage, svc)
		} else {
			// Use INSTALLATION_ID to generate unique bucket name
			return fmt.Sprintf("%s-%s-%s", thisEnvironment.Stage, svc, installationID)
		}
}

func (thisEnvironment Environment) SNS(name, region string) string {
	// TODO: Check: if service name is empty, should this be a fatal error???
	if name == "" {
		log.Warn("SNS Warning: Service string empty")
		return ""
	}
	return fmt.Sprintf("arn:aws:sns:%s:%s:%s", region, thisEnvironment.AccountID, name)
}

func (thisEnvironment Environment) Udomain(service string) string {
	if service == "" {
		log.Warn("Udomain warning:Service string empty")
		return ""
	}

	// We establish the domain for the Installation based on parameters DOMAIN
	// This variable can be edited in the AWS parameter store
	domain := thisEnvironment.GetSecret("DOMAIN")
	log.Infof("Udomain Log: We have a value for DOMAIN in the AWS parameter store: %s", domain)


	// We establish the Stage for the environment based on parameters STAGE
	// This variable can be edited in the AWS parameter store
	stage := thisEnvironment.GetSecret("STAGE")
	log.Infof("Udomain Log: We have a value for STAGE in the AWS parameter store: %s", stage)

// If we have no information on the domain then we stop
		if domain == "" {
			log.Fatal("Udomain fatal: DOMAIN is unset, this is a fatal problem")
		}

	// Based on the Environment we are in we do different things
		switch thisEnvironment.environmentId {
			case EnvDev:
				log.Infof("Udomain Log: We have a defined the link to this service as %s.%s.%s", service, stage, domain)
				return fmt.Sprintf("%s.%s.%s", service, stage, domain)
			case EnvProd:
				log.Infof("Udomain Log: We have a defined the link to this service as %s.%s", service, domain)
				return fmt.Sprintf("%s.%s", service, domain)
			case EnvDemo:
				log.Infof("Udomain Log: We have a defined the link to this service as %s.%s.%s", service, stage, domain)
				return fmt.Sprintf("%s.%s.%s", service, stage, domain)
			default:
				log.Fatal("Udomain fatal: The STAGE for this environment is unknown, this is a fatal problem")
				return ""
		}
}
