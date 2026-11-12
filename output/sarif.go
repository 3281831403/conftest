package output

import (
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/open-policy-agent/conftest/internal/version"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const (
	// Tool information
	toolName     = "conftest"
	toolURI      = "https://github.com/open-policy-agent/conftest"
	sarifVersion = sarif.Version210

	// Result descriptions
	successDesc   = "Policy was satisfied successfully"
	skippedDesc   = "Policy check was skipped"
	failureDesc   = "Policy violation"
	warningDesc   = "Policy warning"
	exceptionDesc = "Policy exception"

	// Exit code descriptions
	exitNoViolations = "No policy violations found"
	exitViolations   = "Policy violations found"
	exitWarnings     = "Policy warnings found"
)

// SARIF represents an Outputter that outputs results in SARIF format.
type SARIF struct {
	writer io.Writer

	// failOnWarn and noFail mirror the test command's flags so that the
	// invocation block reports the same exit code the process will return.
	failOnWarn bool
	noFail     bool
}

// NewSARIF creates a new SARIF with the given writer.
func NewSARIF(w io.Writer) *SARIF {
	return &SARIF{
		writer: w,
	}
}

// NewSARIFWithExitOptions creates a new SARIF configured with the exit code
// semantics used by the invoking command.
func NewSARIFWithExitOptions(w io.Writer, failOnWarn, noFail bool) *SARIF {
	return &SARIF{
		writer:     w,
		failOnWarn: failOnWarn,
		noFail:     noFail,
	}
}

// getRuleID generates a stable rule ID based on namespace and rule type
func getRuleID(namespace string, ruleType string) string {
	return fmt.Sprintf("%s/%s", namespace, ruleType)
}

// getRuleDescription returns the appropriate description based on the rule type
func getRuleDescription(ruleID string) string {
	switch {
	case strings.HasSuffix(ruleID, "/success"):
		return successDesc
	case strings.HasSuffix(ruleID, "/skip"):
		return skippedDesc
	case strings.HasSuffix(ruleID, "/allow"):
		return exceptionDesc
	case strings.HasSuffix(ruleID, "/warn"):
		return warningDesc
	default:
		return failureDesc
	}
}

// addRuleIndex adds a new rule to the SARIF run and returns its index.
func addRuleIndex(run *sarif.Run, ruleID string, result Result, indices map[string]int) int {
	addRule(run, ruleID, result)
	idx := len(run.Tool.Driver.Rules) - 1
	indices[ruleID] = idx
	return idx
}

// addRule adds a new rule to the SARIF run with the given ID and result metadata.
func addRule(run *sarif.Run, ruleID string, result Result) {
	desc := getRuleDescription(ruleID)
	run.AddRule(ruleID).
		WithDescription(desc).
		WithProperties(result.Metadata).
		WithShortDescription(sarif.NewMultiformatMessageString(desc))
}

// addResult adds a result to the SARIF run
func addResult(run *sarif.Run, result Result, namespace, ruleType, level, fileName string, indices map[string]int) {
	ruleID := getRuleID(namespace, ruleType)
	idx, ok := indices[ruleID]
	if !ok {
		idx = addRuleIndex(run, ruleID, result, indices)
	}

	location := sarif.NewPhysicalLocation()
	if loc := result.Location; loc != nil {
		line, _ := strconv.Atoi(loc.Line.String())
		fileName = loc.File
		location.Region = sarif.NewRegion().WithStartLine(line).WithEndLine(line)
	}
	uri := url.URL{Path: filepath.ToSlash(fileName)}
	location.ArtifactLocation = sarif.NewSimpleArtifactLocation(uri.EscapedPath())

	run.CreateResultForRule(ruleID).
		WithRuleIndex(idx).
		WithLevel(level).
		WithMessage(sarif.NewTextMessage(result.Message)).
		AddLocation(sarif.NewLocationWithPhysicalLocation(location))
}

// addExceptionResults renders the violations waived by an exception. When the
// engine recorded the waived violations, each one is reported against the rule
// that produced it and marked with an "external" suppression, preserving the
// original violation message, location and its rule attribution. Exceptions
// without waived violation details fall back to the generic "allow" result.
func addExceptionResults(run *sarif.Run, exception Result, namespace, fileName string, indices map[string]int) {
	ruleName, hasRule := exception.WaivedRule()
	waivedResults := exception.WaivedResults()
	if !hasRule || len(waivedResults) == 0 {
		// Fall back to the message-only metadata, or the generic "allow"
		// result when the engine recorded no waived violations at all.
		waivedMessages := exception.WaivedMessages()
		if len(waivedMessages) == 0 {
			addResult(run, exception, namespace, "allow", "note", fileName, indices)
			return
		}
		for _, message := range waivedMessages {
			waivedResults = append(waivedResults, Result{Message: message})
		}
	}

	severity, _ := exception.Metadata[WaivedSeverityMetadata].(string)
	level := "error"
	if severity == "warning" {
		level = "warning"
	}

	for _, waivedResult := range waivedResults {
		// The exception query string is kept as provenance alongside the
		// metadata produced by the original rule.
		waivedResult.Metadata = mergeMetadata(waivedResult.Metadata, map[string]any{
			"exception": exception.Message,
		})
		addResult(run, waivedResult, namespace, ruleName, level, fileName, indices)

		suppression := sarif.NewSuppression("external")
		// The go-sarif setter for this field is misspelled
		// (WithJustifcation), so set the field directly.
		suppression.Justification = &exception.Message
		run.Results[len(run.Results)-1].AddSuppression(suppression)
	}
}

// mergeMetadata returns a new metadata map containing the entries of both
// inputs. The base map is not modified.
func mergeMetadata(base map[string]any, extra map[string]any) map[string]any {
	merged := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range extra {
		merged[k] = v
	}
	return merged
}

// Output outputs the results in SARIF format.
func (s *SARIF) Output(results CheckResults) error {
	report, err := sarif.New(sarifVersion)
	if err != nil {
		return fmt.Errorf("create sarif report: %w", err)
	}

	// SARIF versions must start with a number, so we remove the "v" prefix.
	toolVersion := strings.TrimPrefix(version.Version, "v")
	driver := sarif.NewVersionedDriver(toolName, toolVersion).WithInformationURI(toolURI)
	run := sarif.NewRun(sarif.Tool{Driver: driver})
	indices := make(map[string]int)

	for _, result := range results {
		// Process failures
		for _, failure := range result.Failures {
			addResult(run, failure, result.Namespace, "deny", "error", result.FileName, indices)
		}

		// Process warnings
		for _, warning := range result.Warnings {
			addResult(run, warning, result.Namespace, "warn", "warning", result.FileName, indices)
		}

		// Process exceptions (treated as successes)
		hasSuccesses := result.Successes > 0
		for _, exception := range result.Exceptions {
			addExceptionResults(run, exception, result.Namespace, result.FileName, indices)
			hasSuccesses = true
		}

		// Don't add success/skip results if there are failures or warnings
		hasErrors := result.HasFailure() || result.HasWarning()
		if hasErrors {
			continue
		}

		// Add success/exception results if there are no failures or warnings
		if hasSuccesses {
			statusResult := Result{
				Message: successDesc,
				Metadata: map[string]any{
					"description": successDesc,
				},
			}
			addResult(run, statusResult, result.Namespace, "success", "none", result.FileName, indices)
		} else {
			statusResult := Result{
				Message: skippedDesc,
				Metadata: map[string]any{
					"description": skippedDesc,
				},
			}
			addResult(run, statusResult, result.Namespace, "skip", "none", result.FileName, indices)
		}
	}

	exitCode := results.ExitCode()
	if s.failOnWarn {
		exitCode = results.ExitCodeFailOnWarn()
	}
	if s.noFail {
		exitCode = 0
	}

	exitDesc := exitNoViolations
	if results.HasFailure() {
		exitDesc = exitViolations
	} else if results.HasWarning() {
		exitDesc = exitWarnings
	}

	run.AddInvocations(sarif.NewInvocation().
		WithExecutionSuccess(exitCode == 0).
		WithExitCode(exitCode).
		WithExitCodeDescription(exitDesc))

	// Add the run to the report
	report.AddRun(run)

	// Write the report
	return report.Write(s.writer)
}
