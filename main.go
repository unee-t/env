package env

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/endpoints"
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

func New(cfg aws.Config) (e Env, err error) {

	defaultRegion, ok := os.LookupEnv("DEFAULT_REGION")
	// the AWS variable `DEFAULT_REGION` is in the format `ap-southeast-1`
	// We can use the repo https://github.com/aws/aws-sdk-go/ to convert this to a format like `ApSoutheast1RegionID`
	// TODO - Check with @kai if the format `ap-southeast-1` is OK or if we need to transform that...
	if ok {
		log.Infof("DEFAULT_REGION overridden by local env: %s", defaultRegion)
	} else {
		defaultRegion = e.GetSecret("DEFAULT_REGION")
	}

	if defaultRegion == "" {
		log.Fatal("DEFAULT_REGION is unset")
	}

	cfg.Region = defaultRegion
	log.Warnf("Env Region: %s", cfg.Region)

	// Save for ssm
	e.Cfg = cfg

	svc := sts.New(cfg)
	input := &sts.GetCallerIdentityInput{}
	req := svc.GetCallerIdentityRequest(input)
	result, err := req.Send(context.TODO())
	if err != nil {
		return e, err
	}

	e.AccountID = aws.StringValue(result.Account)
	log.Infof("Account ID: %s", result.Account)

	e.Stage = e.GetSecret("STAGE")

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
		log.WithField("stage", e.Stage).Error("unknown stage")
		return e, nil
	}
}

func (e Env) Bucket(svc string) string {
	// Most common bucket
	if svc == "" {
		svc = "media"
	}
	installationID := e.GetSecret("INSTALLATION_ID")
	if installationID == "" {
		installationID = "main"
		log.Warnf("Using fallback INSTALLATION_ID: %s: ", installationID)
	}
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
		log.Warn("Service string empty")
		return ""
	}
	return fmt.Sprintf("arn:aws:sns:%s:%s:%s", region, e.AccountID, name)
}

func (e Env) Udomain(service string) string {
	if service == "" {
		log.Warn("Service string empty")
		return ""
	}
	domain := e.GetSecret("DOMAIN")
	if domain == "" {
		domain = "unee-t.com"
		log.Warnf("Using fallback domain: %s: ", domain)
	}
	switch e.Code {
	case EnvDev:
		return fmt.Sprintf("%s.dev.%s", service, domain)
	case EnvProd:
		return fmt.Sprintf("%s.%s", service, domain)
	case EnvDemo:
		return fmt.Sprintf("%s.demo.%s", service, domain)
	default:
		log.Warnf("Udomain warning: Env %d is unknown, resorting to dev", e.Code)
		return fmt.Sprintf("%s.dev.unee-t.com", service)
	}
}

func (e Env) BugzillaDSN() string {
	var mysqlhost string
	valmysqlhost, ok := os.LookupEnv("MYSQL_HOST")
	if ok {
		log.Infof("MYSQL_HOST overridden by local env: %s", valmysqlhost)
		mysqlhost = valmysqlhost
	} else {
		mysqlhost = e.GetSecret("MYSQL_HOST")
	}

	if mysqlhost == "" {
		log.Fatal("MYSQL_HOST is unset")
	}

	var mysqlport string
	valmysqlport, ok := os.LookupEnv("MYSQL_PORT")
	if ok {
		log.Infof("MYSQL_PORT overridden by local env: %s", valmysqlport)
		mysqlport = valmysqlport
	} else {
		mysqlport = e.GetSecret("MYSQL_PORT")
	}

	if mysqlport == "" {
		log.Fatal("MYSQL_PORT is unset")
	}

	var bugzillaDbName string
	valbugzillaDbName, ok := os.LookupEnv("BUGZILLA_DB_NAME")
	if ok {
		log.Infof("BUGZILLA_DB_NAME overridden by local env: %s", valbugzillaDbName)
		bugzillaDbName = valbugzillaDbName
	} else {
		bugzillaDbName = e.GetSecret("BUGZILLA_DB_NAME")
	}

	if bugzillaDbName == "" {
		log.Fatal("BUGZILLA_DB_NAME is unset")
	}

	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?multiStatements=true&sql_mode=TRADITIONAL&timeout=5s&collation=utf8mb4_unicode_520_ci",
		e.GetSecret("BUGZILLA_DB_USER"),
		e.GetSecret("BUGZILLA_DB_PASSWORD"),
		mysqlhost,
		mysqlport,
		bugzillaDbName)
}

// GetSecret is the Golang equivalent for
// aws --profile uneet-dev ssm get-parameters --names API_ACCESS_TOKEN --with-decryption --query Parameters[0].Value --output text

func (e Env) GetSecret(key string) string {

	val, ok := os.LookupEnv(key)
	if ok {
		log.Warnf("%s overridden by local env: %s", key, val)
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
		log.WithError(err).Errorf("failed to retrieve credentials for looking up %s", key)
		return ""
	}
	return aws.StringValue(out.Parameter.Value)
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
			log.Errorf("Token %q != APIAccessToken %q", token, APIAccessToken)
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
