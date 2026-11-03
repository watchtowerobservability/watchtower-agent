package cloud

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestPickNamespacesKeepsDistinctAWSSorted(t *testing.T) {
	got := pickNamespaces([]string{"AWS/Lambda", "Custom/App", "AWS/EC2", "AWS/Lambda", "CWAgent"})
	if fmt.Sprint(got) != "[AWS/EC2 AWS/Lambda]" {
		t.Fatalf("got %v", got)
	}
	many := make([]string, 0, 60)
	for i := range 60 {
		many = append(many, fmt.Sprintf("AWS/S%02d", i))
	}
	if n := len(pickNamespaces(many)); n != maxAutoNamespaces {
		t.Fatalf("cap: %d", n)
	}
	if !isAuto([]string{"AUTO"}) || isAuto([]string{"auto", "AWS/EC2"}) || isAuto(nil) {
		t.Fatal("isAuto")
	}
}

func TestAssumeRoleWrapsCredentialsOnlyWithRole(t *testing.T) {
	base := aws.AnonymousCredentials{}
	cfg := aws.Config{Region: "eu-west-1", Credentials: base}
	assumeRole(&cfg, "", "")
	if cfg.Credentials != base {
		t.Fatal("no role_arn must keep the default chain")
	}
	assumeRole(&cfg, "arn:aws:iam::123456789012:role/watchtower-read", "ext-1")
	if _, ok := cfg.Credentials.(*aws.CredentialsCache); !ok {
		t.Fatalf("role_arn must install an assume-role provider, got %T", cfg.Credentials)
	}
}
