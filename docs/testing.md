# Testing Guidelines

This document provides guidelines for writing and running tests for the Go Backend project.

## Overview

Our testing strategy includes:

1. **Unit Tests**: Test individual components in isolation.
2. **Integration Tests**: Test interactions between components.
3. **API Tests**: Test HTTP endpoints.

Tests are automatically run before each build to ensure code quality and prevent regressions.

## Running Tests

### Basic Test Execution

To run all tests:

```bash
make test
```

### Test with Coverage

To run tests with coverage analysis:

```bash
make test-coverage
```

This will generate a coverage report and open it in your browser.

### CI Tests

For CI environments:

```bash
make ci-test
```

## Writing Tests

### Test Structure

Follow these guidelines when writing tests:

1. **File Naming**: Name test files with `_test.go` suffix, placed in the same package as the code being tested.
2. **Test Function Naming**: Name test functions as `Test<FunctionName>` for unit tests and `Test<Feature>` for integration tests.
3. **Table-Driven Tests**: Use table-driven tests where possible to test multiple scenarios.

### Test Structure Example

```go
func TestSomething(t *testing.T) {
    testCases := []struct {
        name           string
        input          SomeType
        expectedOutput AnotherType
        expectedError  bool
    }{
        {
            name:           "Success case",
            input:          SomeValue,
            expectedOutput: ExpectedValue,
            expectedError:  false,
        },
        {
            name:           "Error case",
            input:          InvalidValue,
            expectedOutput: DefaultValue,
            expectedError:  true,
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // Test logic here
        })
    }
}
```

### Mocking

Use the `github.com/stretchr/testify/mock` package for mocking dependencies. See existing test files for examples.

### Assertions

Use the `github.com/stretchr/testify/assert` package for assertions:

```go
assert.Equal(t, expected, actual, "Values should be equal")
assert.NoError(t, err, "Should not return an error")
```

## API Testing

API tests use the `net/http/httptest` package to create a test server:

```go
router := gin.New()
router.GET("/endpoint", handler.HandleEndpoint)

req, _ := http.NewRequest(http.MethodGet, "/endpoint", nil)
resp := httptest.NewRecorder()
router.ServeHTTP(resp, req)

assert.Equal(t, http.StatusOK, resp.Code)
```

## Test Coverage

Aim for at least 70% test coverage for all new code. Critical components should have higher coverage.

## Pre-commit Checks

Before committing code, run:

```bash
make fmt      # Format code
make lint     # Run linters 
make test     # Run tests
```

## Continuous Integration

The CI pipeline runs tests automatically on each push and pull request. Failed tests will block merging.

## Best Practices

1. **Test Independence**: Each test should be independent of others.
2. **Clean Setup/Teardown**: Initialize and clean up test resources properly.
3. **Clear Assertions**: Make assertions clear and specific.
4. **Test Edge Cases**: Include tests for edge cases and error conditions.
5. **Keep Tests Fast**: Tests should run quickly to maintain development velocity. 