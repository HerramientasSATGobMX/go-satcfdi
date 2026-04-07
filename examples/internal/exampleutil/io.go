package exampleutil

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func Usagef(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(message, "\n") {
		message += "\n"
	}
	_, _ = os.Stderr.WriteString(message)
	os.Exit(2)
}

func Fail(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func JSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	Fail(encoder.Encode(value))
}

func Optional(name string) string {
	return strings.TrimSpace(os.Getenv(name))
}

func Env(name, fallback string) string {
	if value := Optional(name); value != "" {
		return value
	}
	return fallback
}

func Require(name string) string {
	if value := Optional(name); value != "" {
		return value
	}
	Usagef("%s es requerido", name)
	return ""
}

func RequireAny(names ...string) string {
	for _, name := range names {
		if value := Optional(name); value != "" {
			return value
		}
	}
	Usagef("%s es requerido", strings.Join(names, " o "))
	return ""
}

func SplitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}
