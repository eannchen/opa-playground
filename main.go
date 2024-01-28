package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

func main() {
	ctx := context.TODO()

	// policy file
	regoFile, err := os.Open("policy.rego")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer regoFile.Close()
	module, err := io.ReadAll(regoFile)
	if err != nil {
		log.Fatalf("error reading file: %v", err)
	}

	// data file
	jsonFile, err := os.Open("data.json")
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()
	data, err := io.ReadAll(jsonFile)
	if err != nil {
		log.Fatalf("error reading file: %v", err)
	}
	var json map[string]interface{}
	if err := util.UnmarshalJSON([]byte(data), &json); err != nil {
		log.Fatalf("UnmarshalJSON: %v", err)
	}

	query, err := rego.New(
		rego.Query("x = data.policy.authz.allow"),
		rego.Module("policy.authz", string(module)),
		rego.Store(inmem.NewFromObject(json)),
	).PrepareForEval(ctx)
	if err != nil {
		log.Fatalf("initial rego error: %v", err)
	}

	input := map[string]interface{}{
		"user":   "alice",
		"action": "read",
		"object": "id123",
		"type":   "dog",
	}
	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		// Handle evaluation error.
		log.Fatalf("evaluation error: %v", err)
	} else if len(results) == 0 {
		// Handle undefined result.
		log.Fatal("undefined result", err)
	} else if result, ok := results[0].Bindings["x"].(bool); !ok {
		// Handle unexpected result type.
		log.Fatalf("unexpected result type: %v", result)
	} else {
		// Handle result/decision.
		// fmt.Printf("%+v", results) => [{Expressions:[true] Bindings:map[x:true]}]
		fmt.Printf("%+v\n", results)
	}
}
