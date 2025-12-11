package config

import (
	"bytes"
	"strings"

	"github.com/fatih/structs"
	"github.com/jeremywohl/flatten"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// ParseConfig behaves like before (no embedded defaults).
// It just forwards to ParseConfigWithEmbedded with nil.
func ParseConfig[T interface{}](configFilePaths []string) (*T, error) {
	return ParseConfigWithEmbedded[T](configFilePaths, nil)
}

// ParseConfigWithEmbedded tries to load config from disk,
// and if the file is NOT found, falls back to embeddedYAML (if provided).
func ParseConfigWithEmbedded[T interface{}](configFilePaths []string, embeddedYAML []byte) (*T, error) {
	for _, v := range configFilePaths {
		viper.AddConfigPath(v)
	}

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	if err := bindAllConfigKeys[T](); err != nil {
		return nil, err
	}

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		var nfErr viper.ConfigFileNotFoundError
		// ✅ use errors.As instead of a direct type assertion
		if errors.As(err, &nfErr) && len(embeddedYAML) > 0 {
			if err2 := viper.ReadConfig(bytes.NewReader(embeddedYAML)); err2 != nil {
				return nil, errors.Wrap(err2, "failed to load embedded default config")
			}
		} else {
			return nil, err
		}
	}

	var c *T
	if err := viper.Unmarshal(&c); err != nil {
		return nil, errors.Wrap(err, "Unable to decode into struct")
	}

	return c, nil
}

// Workaround for major viper issue with env variables, documented here
// https://github.com/spf13/viper/issues/761
func bindAllConfigKeys[T interface{}]() error {
	var cd T
	// Transform config struct to map
	confMap := structs.Map(cd)

	// Flatten nested conf map
	flat, err := flatten.Flatten(confMap, "", flatten.DotStyle)
	if err != nil {
		return errors.Wrap(err, "Unable to flatten config")
	}

	// Bind each conf field to environment vars
	for key := range flat {
		if err := viper.BindEnv(key); err != nil {
			return errors.Wrapf(err, "Unable to bind env var: %s", key)
		}
	}
	return nil
}
