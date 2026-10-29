package cloud

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTagFilterKeepsOnlyTaggedResources(t *testing.T) {
	calls := 0
	x := &tagIndex{load: func(context.Context) ([]Tagged, error) {
		calls++
		return []Tagged{{ARN: "arn:aws:lambda:eu-west-1:1:function:orders"}, {ARN: "arn:aws:ec2:eu-west-1:1:instance/i-0abc"}}, nil
	}}
	refs := []metricRef{
		{Namespace: "AWS/Lambda", Name: "Errors", Dims: []dim{{"FunctionName", "orders"}}},
		{Namespace: "AWS/Lambda", Name: "Errors", Dims: []dim{{"FunctionName", "other"}}},
		{Namespace: "AWS/EC2", Name: "CPUUtilization", Dims: []dim{{"InstanceId", "i-0abc"}}},
	}
	now := time.Now()
	if got := x.filter(context.Background(), refs, now); len(got) != 2 || got[0].Dims[0].Value != "orders" {
		t.Fatalf("filtered: %+v", got)
	}
	x.filter(context.Background(), refs, now.Add(time.Minute))
	if calls != 1 {
		t.Fatalf("index reloaded within its TTL: %d", calls)
	}
	var none *tagIndex
	if len(none.filter(context.Background(), refs, now)) != 3 {
		t.Fatal("no filter keeps everything")
	}
	down := &tagIndex{load: func(context.Context) ([]Tagged, error) { return nil, errors.New("denied") }}
	if len(down.filter(context.Background(), refs, now)) != 0 {
		t.Fatal("a failed tag lookup must not widen the scope")
	}
}
