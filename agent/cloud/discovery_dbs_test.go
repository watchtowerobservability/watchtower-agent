package cloud

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func byID(es []Entity, id string) *Entity {
	for i := range es {
		if es[i].Attrs["cloud.resource_id"] == id {
			return &es[i]
		}
	}
	return nil
}

func TestRDSDiscoveryMapsInstancesAndTags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f, _ := url.ParseQuery(string(b))
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch {
		case f.Get("Action") == "DescribeDBInstances" && f.Get("Marker") == "":
			fmt.Fprint(w, `<DescribeDBInstancesResponse><DescribeDBInstancesResult><Marker>m2</Marker><DBInstances><DBInstance>
<DBInstanceIdentifier>orders</DBInstanceIdentifier><Engine>postgres</Engine><EngineVersion>16.3</EngineVersion>
<DBInstanceArn>arn:aws:rds:eu-west-1:1:db:orders</DBInstanceArn>
<TagList><Tag><Key>team</Key><Value>core</Value></Tag></TagList></DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`)
		case f.Get("Action") == "DescribeDBInstances":
			fmt.Fprint(w, `<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>
<DBInstanceIdentifier>cache</DBInstanceIdentifier><Engine>mysql</Engine><EngineVersion>8.0</EngineVersion>
<DBInstanceArn>arn:aws:rds:eu-west-1:1:db:cache</DBInstanceArn></DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`)
		default:
			fmt.Fprint(w, `<DescribeDBClustersResponse><DescribeDBClustersResult><DBClusters><DBCluster>
<DBClusterIdentifier>aur</DBClusterIdentifier><Engine>aurora-postgresql</Engine><EngineVersion>15.4</EngineVersion>
<DBClusterArn>arn:aws:rds:eu-west-1:1:cluster:aur</DBClusterArn></DBCluster></DBClusters></DescribeDBClustersResult></DescribeDBClustersResponse>`)
		}
	}))
	defer srv.Close()
	es := DiscoverDatabases(context.Background(), DBConfig{AWS: &rdsConfig{
		Region: "eu-west-1", Endpoint: srv.URL, AccessKeyID: "AKID", SecretAccessKey: "s",
	}})
	if len(es) != 3 {
		t.Fatalf("want 3 entities, got %d", len(es))
	}
	o := byID(es, "arn:aws:rds:eu-west-1:1:db:orders")
	if o == nil || o.Attrs["db.system"] != "postgresql" || o.Attrs["cloud.tag.team"] != "core" ||
		o.Attrs["db.version"] != "16.3" || o.Attrs["cloud.provider"] != "aws" || o.Attrs["cloud.region"] != "eu-west-1" {
		t.Fatalf("orders: %+v", o)
	}
	if c := byID(es, "arn:aws:rds:eu-west-1:1:cluster:aur"); c == nil || c.Attrs["db.system"] != "postgresql" {
		t.Fatalf("aurora cluster: %+v", c)
	}
	rec := &sink.Recorder{}
	EmitEntities(rec, es, time.Now())
	if len(rec.Samples) != 3 || rec.Samples[0].Name != "cloud.resource.info" {
		t.Fatalf("emit: %+v", rec.Samples)
	}
}

func TestAzureFlexibleServerListPaged(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
		case r.Header.Get("Authorization") != "Bearer tok":
			w.WriteHeader(http.StatusUnauthorized)
		case strings.HasSuffix(r.URL.Path, "/Microsoft.DBforPostgreSQL/flexibleServers"):
			if r.URL.Query().Get("page") == "" {
				_, _ = fmt.Fprintf(w, `{"value":[{"id":"/subscriptions/s1/pg1","name":"pg1","location":"westeurope","tags":{"env":"prod"},"properties":{"version":"16"}}],"nextLink":"%s%s?api-version=x&page=2"}`, srv.URL, r.URL.Path)
				return
			}
			_, _ = io.WriteString(w, `{"value":[{"id":"/subscriptions/s1/pg2","name":"pg2","location":"westeurope","properties":{"version":"15"}}],"nextLink":"https://evil.example/x"}`)
		default:
			_, _ = io.WriteString(w, `{"value":[]}`)
		}
	}))
	defer srv.Close()
	es := DiscoverDatabases(context.Background(), DBConfig{Azure: &azureDBConfig{
		TenantID: "t", ClientID: "c", ClientSecret: "s", SubscriptionID: "s1", LoginEndpoint: srv.URL, Endpoint: srv.URL,
	}})
	if len(es) != 2 {
		t.Fatalf("want both pages and no foreign nextLink, got %d", len(es))
	}
	if e := byID(es, "/subscriptions/s1/pg1"); e == nil || e.Attrs["db.system"] != "postgresql" || e.Attrs["cloud.tag.env"] != "prod" {
		t.Fatalf("pg1: %+v", e)
	}
}

func TestCloudSQLListSkipsDeleted(t *testing.T) {
	_, keyPEM := testKeyPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
		case r.URL.Query().Get("pageToken") == "":
			_, _ = io.WriteString(w, `{"items":[{"name":"a","state":"RUNNABLE","region":"us-central1","databaseVersion":"POSTGRES_15","settings":{"userLabels":{"app":"x"}}},
{"name":"gone","state":"PENDING_DELETE","databaseVersion":"MYSQL_8_0"}],"nextPageToken":"p2"}`)
		default:
			_, _ = io.WriteString(w, `{"items":[{"name":"b","state":"RUNNABLE","region":"us-central1","databaseVersion":"MYSQL_8_0"}]}`)
		}
	}))
	defer srv.Close()
	c := &cloudSQLConfig{Project: "p", Endpoint: srv.URL}
	c.ServiceAccount.ClientEmail, c.ServiceAccount.PrivateKey, c.ServiceAccount.TokenURI = "sa@p", keyPEM, srv.URL+"/token"
	es := DiscoverDatabases(context.Background(), DBConfig{GCP: c})
	if len(es) != 2 || byID(es, "projects/p/instances/gone") != nil {
		t.Fatalf("deleted instance must be skipped: %+v", es)
	}
	if a := byID(es, "projects/p/instances/a"); a == nil || a.Attrs["db.system"] != "postgresql" || a.Attrs["cloud.tag.app"] != "x" {
		t.Fatalf("a: %+v", a)
	}
}

func TestDiscoveryErrorKeepsLastGood(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, `<R><DescribeDBInstancesResult><DBInstances><DBInstance><DBInstanceIdentifier>d</DBInstanceIdentifier>
<Engine>postgres</Engine><DBInstanceArn>arn:d</DBInstanceArn></DBInstance></DBInstances></DescribeDBInstancesResult></R>`)
	}))
	defer srv.Close()
	d := NewDBDiscovery(DBConfig{AWS: &rdsConfig{Region: "r", Endpoint: srv.URL, AccessKeyID: "a", SecretAccessKey: "b"}})
	if n := len(d.Discover(context.Background())); n != 1 {
		t.Fatalf("first pass: %d", n)
	}
	fail.Store(true)
	if n := len(d.Discover(context.Background())); n != 1 {
		t.Fatalf("a failed refresh must keep the last good answer, got %d", n)
	}
}
