package main

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/endpoints"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Env int

var (
	EnvUnknown Env = 0 // Oops
	EnvDev     Env = 1 // Development aka Staging
	EnvProd    Env = 2 // Production
	EnvDemo    Env = 3 // Demo, which is like Production, for prospective customers to try
)

func main() {
	cfg, err := external.LoadDefaultAWSConfig(external.WithSharedConfigProfile("uneet-dev"))
	if err != nil {
		log.Fatal(err)
		return
	}

	cfg.Region = endpoints.ApSoutheast1RegionID

	// Assuming each account should have a STAGE variable set
	stage, err := getSecret(cfg, "STAGE")
	if err != nil {
		log.Fatal(err)
		return
	}

	fmt.Println("STAGE:", stage)

	code, err := envcode(cfg)
	if err != nil {
		log.Fatal(err)
		return
	}
	fmt.Println(udomain(code, "whatever"))

}

func envcode(cfg aws.Config) (Env, error) {
	svc := sts.New(cfg)
	input := &sts.GetCallerIdentityInput{}

	req := svc.GetCallerIdentityRequest(input)
	result, err := req.Send()
	if err != nil {
		return 0, err
	}

	log.Printf("Account: %v", result)

	// https://github.com/unee-t/processInvitations/blob/master/sql/1_process_one_invitation_all_scenario_v3.0.sql#L16
	switch accountID := aws.StringValue(result.Account); accountID {
	case "812644853088":
		return EnvDev, nil
	case "192458993663":
		return EnvProd, nil
	case "915001051872":
		return EnvDemo, nil
	default:
		// Resort to staging if we don't recognise the account
		log.Printf("Warning: Account ID %s is unknown, resorting to dev", accountID)
		return EnvDev, nil
	}
}

func udomain(env Env, service string) string {
	if service == "" {
		return ""
	}
	switch env {
	case EnvDev:
		return fmt.Sprintf("%s.dev.unee-t.com", service)
	case EnvProd:
		return fmt.Sprintf("%s.unee-t.com", service)
	case EnvDemo:
		return fmt.Sprintf("%s.demo.unee-t.com", service)
	default:
		log.Printf("Warning: Env %d is unknown, resorting to dev", env)
		return fmt.Sprintf("%s.dev.unee-t.com", service)
	}

}

func getSecret(cfg aws.Config, store string) (string, error) {
	ps := ssm.New(cfg)
	in := &ssm.GetParameterInput{
		Name:           aws.String(store),
		WithDecryption: aws.Bool(true),
	}
	req := ps.GetParameterRequest(in)
	out, err := req.Send()
	if err != nil {
		return "", err
	}
	return aws.StringValue(out.Parameter.Value), nil
}
