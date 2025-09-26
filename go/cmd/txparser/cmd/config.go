// Package cmd
package cmd

import (
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	RawTx string
}

func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}
	rawTx := viper.GetString("RAW_TX")
	if rawTx == "" {
		rawTx = os.Getenv("RAW_TX")
	}
	return &Config{
		RawTx: rawTx,
	}, nil
}
