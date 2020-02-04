package env

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Env is how we manage our differing {dev,demo,prod} AWS accounts
type Env struct {
	Code      EnvCode
	Cfg       aws.Config
	AccountID string
	Stage     string
}

type EnvCode int

// https://github.com/unee-t/processInvitations/blob/master/sql/1_process_one_invitation_all_scenario_v3.0.sql#L12-L16
const (
	EnvUnknown EnvCode = iota // Oops
	EnvDev                    // Development aka Staging
	EnvProd                   // Production
	EnvDemo                   // Demo, which is like Production, for prospective customers to try
)

// GetSecret is the Golang equivalent for
// aws --profile your-aws-cli-profile ssm get-parameters --names API_ACCESS_TOKEN --with-decryption --query Parameters[0].Value --output text

func (e Env) GetSecret(key string) string {

	val, ok := os.LookupEnv(key)
	if ok {
		log.Warnf("GetSecret Warning: No need to query AWS parameter store: %s overridden by local env", key)
		return val
	}
	// Ideally environment above is set to avoid costly ssm (parameter store) lookups

	ps := ssm.New(e.Cfg)
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
func NewConfig(cfg aws.Config) (e Env, err error) {

	// Save for ssm
		e.Cfg = cfg

		svc := sts.New(cfg)
		input := &sts.GetCallerIdentityInput{}
		req := svc.GetCallerIdentityRequest(input)
		result, err := req.Send(context.TODO())
		if err != nil {
			return e, err
		}

	// We get the ID of the AWS account we use
		e.AccountID = aws.StringValue(result.Account)
		log.Infof("NewConfig Log: The AWS Account ID for this environment is: %s", e.AccountID)

	// We get the value for the DEFAULT_REGION
		defaultRegion, ok := os.LookupEnv("DEFAULT_REGION")
		if ok {
			log.Infof("NewConfig Log: DEFAULT_REGION was overridden by local env: %s", defaultRegion)
		} else {
			log.Fatal("NewConfig fatal: DEFAULT_REGION is unset as an environment variable, this is a fatal problem")
		}

		cfg.Region = defaultRegion
		log.Infof("NewConfig Log: The AWS region for this environment has been set to: %s", cfg.Region)

	// We get the value for the STAGE
		stage, ok := os.LookupEnv("STAGE")
		if ok {
			log.Infof("NewConfig Log: STAGE was overridden by local env: %s", stage)
		} else {
			log.Fatal("NewConfig fatal: STAGE is unset as an environment variable, this is a fatal problem")
		}

		e.Stage = stage

	// Based on the value of the STAGE variable we do different things
		switch e.Stage {
		case "dev":
			e.Code = EnvDev
			return e, nil
		case "prod":
			e.Code = EnvProd
			return e, nil
		case "demo":
			e.Code = EnvDemo
			return e, nil
		default:
			log.WithField("stage", e.Stage).Error("NewConfig Error: unknown stage")
			return e, nil
		}
}

func (e Env) Bucket(svc string) string {

	// Most common bucket
		if svc == "" {
			svc = "media"
		}

	// We establish the ID of the Installation based on parameters INSTALLATION_ID
	// This variable can be edited in the AWS parameter store
		installationID := e.GetSecret("INSTALLATION_ID")

	// If we have no installation ID we stop
		if installationID == "" {
			log.Fatal("Bucket fatal: installationID is unset, this is a fatal problem")
		}

	// To preserve legacy in case this is the Public Unee-T installation
		if installationID == "main" {
			// Preserve original bucket names
			return fmt.Sprintf("%s-%s-unee-t", e.Stage, svc)
		} else {
			// Use INSTALLATION_ID to generate unique bucket name
			return fmt.Sprintf("%s-%s-%s", e.Stage, svc, installationID)
		}
}

func (e Env) SNS(name, region string) string {
	if name == "" {
		log.Warn("SNS Wraning: Service string empty")
		return ""
	}
	return fmt.Sprintf("arn:aws:sns:%s:%s:%s", region, e.AccountID, name)
}

func (e Env) Udomain(service string) string {
	if service == "" {
		log.Warn("Udomain warning:Service string empty")
		return ""
	}

	// We establish the domain for the Installation based on parameters DOMAIN
	// This variable can be edited in the AWS parameter store
		domain := e.GetSecret("DOMAIN")

	// If we have no information on the domain then we stop
		if domain == "" {
			log.Fatal("Udomain fatal:domain is unset, this is a fatal problem")
		}

	// Based on the Environment we are in we do different things
		switch e.Code {
			case EnvDev:
				return fmt.Sprintf("%s.dev.%s", service, domain)
			case EnvProd:
				return fmt.Sprintf("%s.%s", service, domain)
			case EnvDemo:
				return fmt.Sprintf("%s.demo.%s", service, domain)
			default:
				log.Fatal("Udomain fatal: Env is unknown, this is a fatal problem")
				return ""
		}
}

func (e Env) BugzillaDSN() string {

	// Get the value of the variable BUGZILLA_DB_USER
		var bugzillaDbUser string
		valbugzillaDbUser, ok := os.LookupEnv("BUGZILLA_DB_USER")
		if ok {
			bugzillaDbUser = valbugzillaDbUser
			log.Infof("BugzillaDSN Log: BUGZILLA_DB_USER was overridden by local env: %s", valbugzillaDbUser)
		} else {
			log.Fatal("BugzillaDSN Fatal: BUGZILLA_DB_USER is unset as an environment variable, this is a fatal problem")
		}

	// Get the value of the variable 
		var bugzillaDbPassword string
		valbugzillaDbPassword, ok := os.LookupEnv("BUGZILLA_DB_PASSWORD")
		if ok {
			bugzillaDbPassword = valbugzillaDbPassword
			log.Infof("BugzillaDSN Log: BUGZILLA_DB_PASSWORD was overridden by local env: **hidden_secret**")
		} else {
			log.Fatal("BugzillaDSN Fatal: BUGZILLA_DB_PASSWORD is unset as an environment variable, this is a fatal problem")
		}
	
	// Get the value of the variable 
		var mysqlhost string
		valmysqlhost, ok := os.LookupEnv("MYSQL_HOST")
		if ok {
			mysqlhost = valmysqlhost
			log.Infof("BugzillaDSN Log: MYSQL_HOST was overridden by local env: %s", valmysqlhost)
		} else {
			mysqlhost = e.GetSecret("MYSQL_HOST")
			log.Fatal("BugzillaDSN Fatal: MYSQL_HOST is unset as an environment variable, this is a fatal problem")
		}

	// Get the value of the variable 
		var mysqlport string
		valmysqlport, ok := os.LookupEnv("MYSQL_PORT")
		if ok {
			mysqlport = valmysqlport
			log.Infof("BugzillaDSN Log: MYSQL_PORT was overridden by local env: %s", valmysqlport)
		} else {
			mysqlport = e.GetSecret("MYSQL_PORT")
			log.Fatal("BugzillaDSN Fatal: MYSQL_PORT is unset as an environment variable, this is a fatal problem")
		}

	// Get the value of the variable 
		var bugzillaDbName string
		valbugzillaDbName, ok := os.LookupEnv("BUGZILLA_DB_NAME")
		if ok {
			bugzillaDbName = valbugzillaDbName
			log.Infof("BugzillaDSN Log: BUGZILLA_DB_NAME was overridden by local env: %s", valbugzillaDbName)
		} else {
			bugzillaDbName = e.GetSecret("BUGZILLA_DB_NAME")
			log.Fatal("BugzillaDSN Fatal: BUGZILLA_DB_NAME is unset as an environment variable, this is a fatal problem")
		}

	// Build the string that will allow connection to the BZ database
		return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?multiStatements=true&sql_mode=TRADITIONAL&timeout=15s&collation=utf8mb4_unicode_520_ci",
			bugzillaDbUser,
			bugzillaDbPassword,
			mysqlhost,
			mysqlport,
			bugzillaDbName)
}

// Protect using: curl -H 'Authorization: Bearer secret' style
// Modelled after https://github.com/apex/up-examples/blob/master/oss/golang-basic-auth/main.go#L16
func Protect(h http.Handler, APIAccessToken string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string
		// Get token from the Authorization header
		// format: Authorization: Bearer
		tokens, ok := r.Header["Authorization"]
		if ok && len(tokens) >= 1 {
			token = tokens[0]
			token = strings.TrimPrefix(token, "Bearer ")
		}
		if token == "" || token != APIAccessToken {
			log.Errorf("Protect Error: Token %q != APIAccessToken %q", token, APIAccessToken)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Towr is a workaround for gorilla/pat: https://stackoverflow.com/questions/50753049/
// Wish I could make this simpler
func Towr(h http.Handler) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }
}