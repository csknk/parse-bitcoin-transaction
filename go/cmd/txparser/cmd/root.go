package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/csknk/parse-bitcoin-transaction/transaction"
)

func NewRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "parse-tx",
		Short: "Parse a Bitcoin transaction",
		Long: `Parse a Bitcoin transaction from a provided raw transaction string.
You can provide the raw transaction in one of the following ways:
1. As a command-line argument: parse-tx "raw_transaction_string"
2. As an environment variable: export RAW_TX="raw_transaction_string"
3. In a config.yaml file with a raw_tx key.`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := runRoot(args); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v", err)
			}
		},
	}
}

func runRoot(args []string) error {
	rawTx, err := rawTx(args)
	if err != nil {
		log.Fatal(fmt.Errorf("rawTx not available: %w", err))
	}
	tx, err := transaction.NewTransaction(rawTx)
	if err != nil {
		return fmt.Errorf(
			"error building transaction with transaction.NewTransaction for %s: %w",
			rawTx,
			err,
		)
	}
	if err = tx.Parse(); err != nil {
		return fmt.Errorf("error parsing transaction %v: %w", tx, err)
	}
	b, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("error marshalling transaction to JSON: %w", err)
	}
	fmt.Println(string(b))
	return nil
}

func rawTx(args []string) (string, error) {
	var rawTx string
	if len(args) > 0 {
		rawTx = args[0]
	} else {
		cfg, err := LoadConfig()
		if err != nil {
			return "", err
		}
		rawTx = cfg.RawTx
	}
	if rawTx == "" {
		return rawTx, fmt.Errorf("no transaction data provided")
	}
	return rawTx, nil
}
