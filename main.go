package env

import (
	"fmt"
	"net/http"
	"os"

	"github.com/apex/log"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Env is how we manage our differing {dev,demo,prod} AWS accounts
type Env struct {
	Code EnvCode
	cfg  aws.Config
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

	// Save for ssm
	e.cfg = cfg

	svc := sts.New(cfg)
	input := &sts.GetCallerIdentityInput{}

	req := svc.GetCallerIdentityRequest(input)
	result, err := req.Send()
	if err != nil {
		return e, err
	}

	log.Infof("Account: %v", result)

	switch accountID := aws.StringValue(result.Account); accountID {
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
		log.Errorf("Warning: Account ID %s is unknown, resorting to dev", accountID)
		return e, nil
	}
}

func (e Env) Udomain(service string) string {
	if service == "" {
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
		log.Warnf("Warning: Env %d is unknown, resorting to dev", e.Code)
		return fmt.Sprintf("%s.dev.unee-t.com", service)
	}

}

func (e Env) GetSecret(store string) string {

	val, ok := os.LookupEnv(store)
	if ok {
		log.Warnf("%s overridden by local env: %s", store, val)
		return val
	}

	ps := ssm.New(e.cfg)
	in := &ssm.GetParameterInput{
		Name:           aws.String(store),
		WithDecryption: aws.Bool(true),
	}
	req := ps.GetParameterRequest(in)
	out, err := req.Send()
	if err != nil {
		log.WithError(err).Fatalf("failed to retrieve credentials for looking up %s", store)
		return ""
	}
	return aws.StringValue(out.Parameter.Value)
}

func Protect(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()

		match := user == "tobi" && pass == "ferret"

		if !ok || !match {
			w.Header().Set("WWW-Authenticate", `Basic realm="Ferret Land"`)
			http.Error(w, `Unauthorized: Use "tobi" and "ferret" :)`, http.StatusUnauthorized)
			return
		}

		h.ServeHTTP(w, r)
	})
}
