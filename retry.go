package gorestly

import (
	"time"

	"github.com/prometheus/common/model"
	"resty.dev/v3"
)

// RestyRetryConfig represents the retry policy of request.
type RestyRetryConfig struct {
	// Number of retry count. Defaults to 0 (no retry).
	Count int `json:"count,omitempty" mapstructure:"count" yaml:"count,omitempty"`
	// The default wait time for sleep before retrying. Default is 100 milliseconds.
	WaitTime *model.Duration `json:"wait_time,omitempty" jsonschema:"nullable,type=string,pattern=^((([0-9]+h)?([0-9]+m)?([0-9]+s))|(([0-9]+h)?([0-9]+m))|([0-9]+h))$" mapstructure:"wait_time" yaml:"wait_time,omitempty"`
	// The max wait time for sleep before retrying. Default is 2000 milliseconds.
	MaxWaitTime *model.Duration `json:"max_wait_time,omitempty" jsonschema:"nullable,type=string,pattern=^((([0-9]+h)?([0-9]+m)?([0-9]+s))|(([0-9]+h)?([0-9]+m))|([0-9]+h))$" mapstructure:"max_wait_time" yaml:"max_wait_time,omitempty"`
}

func setRestyRetryConfig(client *resty.Client, conf *RestyRetryConfig) *resty.Client {
	if conf == nil || conf.Count == 0 {
		return client
	}

	client = client.SetRetryCount(conf.Count)

	if conf.WaitTime != nil && *conf.WaitTime > 0 {
		client = client.SetRetryWaitTime(time.Duration(*conf.WaitTime))
	}

	if conf.MaxWaitTime != nil && *conf.MaxWaitTime > 0 {
		client = client.SetRetryMaxWaitTime(time.Duration(*conf.MaxWaitTime))
	}

	return client
}
