package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/golang-jwt/jwt"
)

const (
	LocalTimeZoneInfo = "America/New_York"
	SESSION           = "IRSA_CREDS_SESSION"
)

func locTime(name string, utcTime time.Time) time.Time {
	loc, err := time.LoadLocation(name)
	if err != nil {
		panic(err)
	}
	return utcTime.In(loc)
}

func runEcrOps() {
	ecrRepo := os.Getenv("ECR_REPO")
	fmt.Println("Region: ", ecrRepo)

	region := os.Getenv("AWS_REGION")
	fmt.Println("Region: ", region)

	roleArn := os.Getenv("AWS_ROLE_ARN")
	fmt.Println("Role ARN: ", roleArn)

	tokenFilePath := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	fmt.Println("Token File Path: ", tokenFilePath)

	stsEndpoints := os.Getenv("AWS_STS_REGIONAL_ENDPOINTS")
	fmt.Println("STS Endpoints: ", stsEndpoints)

	ecrAccount := os.Getenv("ECR_ACCOUNT_ID")
	fmt.Println("ECR Account: ", ecrAccount)

	ecrRegion := os.Getenv("ECR_REGION")
	fmt.Println("ECR Region: ", ecrRegion)

	podName := os.Getenv("POD_NAME")
	fmt.Println("Pod name: ", podName)

	if region == "" || roleArn == "" || tokenFilePath == "" {
		panic("failed to load ENV")
	}
	
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region),
		config.WithWebIdentityRoleCredentialOptions(func(options *stscreds.WebIdentityRoleOptions) {
			options.RoleSessionName = SESSION + "@" + podName
		}))
	if err != nil {
		panic("failed to load config, " + err.Error())
	}

	client := sts.NewFromConfig(cfg)

	credsCache := aws.NewCredentialsCache(stscreds.NewWebIdentityRoleProvider(
		client,
		roleArn,
		stscreds.IdentityTokenFile(tokenFilePath),
		func(o *stscreds.WebIdentityRoleOptions) {
			o.RoleSessionName = SESSION
		}))

	creds, err := credsCache.Retrieve(ctx)
	if err != nil {
		fmt.Printf("error retrieving creds, %v", err)
		return
	}

	if !creds.HasKeys() {
		panic("no credential keys returned")
	}

	//fmt.Println(value)
	fmt.Printf("AccessKeyID: %s\n", creds.AccessKeyID)
	fmt.Printf("SecretAccessKey: %s\n", creds.SecretAccessKey)
	fmt.Printf("SessionToken: %s\n", creds.SessionToken)
	fmt.Printf("Expires: %v\n", creds.Expires)
	fmt.Printf("Source: %s\n", creds.Source)

	//ECR Ops
	ecrClient := ecr.NewFromConfig(cfg)

	input := &ecr.ListImagesInput{
		RepositoryName: aws.String(ecrRepo),
	}

	resp, err := ecrClient.ListImages(ctx, input)
	if err != nil {
		// handle this
		log.Fatal(err)
		return
	}

	fmt.Println("Listing tags in ", aws.String(ecrRepo))
	for _, img := range resp.ImageIds {
		fmt.Println("Digest: ", *img.ImageDigest)

		//Added to prevent trying to dereference nil pointer for untagged images
		if img.ImageTag != nil {
			fmt.Println("Tag: ", *img.ImageTag)
		}
	}

	// Remote ECR Ops
	result, err := ecrClient.ListImages(ctx, &ecr.ListImagesInput{
		RepositoryName: aws.String(ecrRepo),
		Filter:         nil,
		MaxResults:     nil,
		NextToken:      nil,
		RegistryId:     aws.String(ecrAccount),
	})

	if err != nil {
		// handle this
		log.Fatal(err)
		return
	}

	fmt.Println(result.ResultMetadata)

	for _, img := range result.ImageIds {
		fmt.Println("Digest: ", *img.ImageDigest)

		//Added to prevent trying to dereference nil pointer for untagged images
		if img.ImageTag != nil {
			fmt.Println("Tag: ", *img.ImageTag)
		}
	}

	//ECR Auth Token
	tokenOutput, err := ecrClient.GetAuthorizationToken(ctx, nil)
	if err != nil {
		log.Fatal(err)
		return
	}

	ecrAuthToken := tokenOutput.AuthorizationData[0]

	fmt.Println("ECR Auth Token: ", *ecrAuthToken.AuthorizationToken)
	rawDecodedText, err := base64.StdEncoding.DecodeString(*ecrAuthToken.AuthorizationToken)
	if err != nil {
		panic(err)
	}
	decodedAuthToken := string(rawDecodedText)
	fmt.Println("Decoded Auth Token: ", decodedAuthToken)
	ecrAuthCredentials := strings.Split(decodedAuthToken, ":")
	fmt.Printf("ECR Credentials: username=%s, password=%s\n", ecrAuthCredentials[0], ecrAuthCredentials[1])
	fmt.Println("ECR Auth Expiry: ", locTime(LocalTimeZoneInfo, *ecrAuthToken.ExpiresAt))
	fmt.Println("ECR Proxy Endpoint: ", *ecrAuthToken.ProxyEndpoint)
}

// Example from https://github.com/golang-jwt/jwt
func runJwtOps() {
	var hmacSampleSecret []byte

	tokenPath := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	if tokenPath == "" {
		fmt.Println("token file path empty")
		return
	}

	tokenBytes, err := os.ReadFile(tokenPath)

	if err != nil {
		fmt.Printf("token file could not be read, %v", err)
		return
	}

	tokenString := string(tokenBytes)

	fmt.Printf("token: %s", tokenString)

	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return hmacSampleSecret, nil
	})

	//if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
	//	fmt.Println(claims["foo"], claims["nbf"])
	//} else {
	//	fmt.Println(err)
	//}

	fmt.Println(token)
}

func runHttpOps() {
	fs := http.FileServer(http.Dir("/"))
	http.Handle("/", fs)

	log.Println("Listening on port 8080...")

	f, err := os.OpenFile("/tmp/log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)

	log.Println("Listening on port 8080...")

	log.Println("This is a test log entry")

	http.ListenAndServe(":8080", nil)
}

func main() {
	runJwtOps()
	runEcrOps()
	runHttpOps()
}
