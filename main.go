package main

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/ssmiface"
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

	ssm := ssm.New(cfg)

	// Assuming each account should have a STAGE variable set
	stage, err := getSecret(ssm, "STAGE")
	if err != nil {
		log.Fatal(err)
		return
	}

	fmt.Println("STAGE:", stage)

	svc := sts.New(cfg)
	input := &sts.GetCallerIdentityInput{}

	req := svc.GetCallerIdentityRequest(input)
	result, err := req.Send()
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}

	fmt.Println(result)

}

func getSecret(ssmapi ssmiface.SSMAPI, store string) (string, error) {
	in := &ssm.GetParameterInput{
		Name:           aws.String(store),
		WithDecryption: aws.Bool(true),
	}
	req := ssmapi.GetParameterRequest(in)
	out, err := req.Send()
	if err != nil {
		return "", err
	}
	return aws.StringValue(out.Parameter.Value), nil
}
