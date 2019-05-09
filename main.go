package env

import (
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

	// Force Singapore
	cfg.Region = endpoints.ApSoutheast1RegionID
	log.Debugf("Env Region: %s", cfg.Region)

	// Save for ssm
	e.Cfg = cfg

	svc := sts.New(cfg)
	input := &sts.GetCallerIdentityInput{}

	req := svc.GetCallerIdentityRequest(input)
	result, err := req.Send()
	if err != nil {
		e.Code = EnvDemo
		log.Warnf("Assuming local development, set Code to demo: %d", e.Code)
		return e, err
	}

	log.Infof("Account: %v", result)
	e.AccountID = aws.StringValue(result.Account)

	switch e.AccountID {
	case "812644853088":
		e.Code = EnvDev
		return e, nil
	case "192458993663":
		e.Code = EnvProd
		return e, nil
	case "915001051872":
		e.Code = EnvDemo
		return e, nil
	default:
		// Resort to staging if we don't recognise the account
		log.Errorf("Warning: Account ID %s is unknown", e.AccountID)
		return e, nil
	}
}

func (e Env) Bucket(svc string) string {
	// Most common bucket
	if svc == "" {
		svc = "media"
	}
	switch e.Code {
	case EnvProd:
		return fmt.Sprintf("prod-%s-unee-t", svc)
	case EnvDemo:
		return fmt.Sprintf("demo-%s-unee-t", svc)
	default:
		return fmt.Sprintf("dev-%s-unee-t", svc)
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
	switch e.Code {
	case EnvDev:
		return fmt.Sprintf("%s.dev.unee-t.com", service)
	case EnvProd:
		return fmt.Sprintf("%s.unee-t.com", service)
	case EnvDemo:
		return fmt.Sprintf("%s.demo.unee-t.com", service)
	default:
		log.Warnf("Udomain warning: Env %d is unknown, resorting to dev", e.Code)
		return fmt.Sprintf("%s.dev.unee-t.com", service)
	}
}

// GetSecret is the Golang equivalent for
// aws --profile uneet-dev ssm get-parameters --names API_ACCESS_TOKEN --with-decryption --query Parameters[0].Value --output text
func (e Env) GetSecret(key string) string {

	val, ok := os.LookupEnv(key)
	if ok {
		log.Warnf("%s overridden by local env: %s", key, val)
		return val
	}

	ps := ssm.New(e.Cfg)
	in := &ssm.GetParameterInput{
		Name:           aws.String(key),
		WithDecryption: aws.Bool(true),
	}
	req := ps.GetParameterRequest(in)
	out, err := req.Send()
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
