package main

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go/aws/endpoints"
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

	domain, err := udomain(cfg, "foobar")
	if err != nil {
		log.Fatal(err)
		return
	}
	fmt.Println(domain)

}

func udomain(cfg aws.Config, service string) (string, error) {
	svc := sts.New(cfg)
	input := &sts.GetCallerIdentityInput{}

	req := svc.GetCallerIdentityRequest(input)
	result, err := req.Send()
	if err != nil {
		return "", err
	}

	log.Printf("Account: %v", result)

	switch accountID := aws.StringValue(result.Account); accountID {
	case "192458993663":
		return fmt.Sprintf("%s.unee-t.com", service), nil
	case "915001051872":
		return fmt.Sprintf("%s.demo.unee-t.com", service), nil
	case "812644853088":
		return fmt.Sprintf("%s.dev.unee-t.com", service), nil
	default:
		return fmt.Sprintf("%s.dev.unee-t.com", service), nil
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
