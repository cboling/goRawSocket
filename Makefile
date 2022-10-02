#
# Copyright (c) 2021 - present.  Boling Consulting Solutions (bcsw.net)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# set default shell
SHELL = bash -e -o pipefail

# Base directory settings
THIS_MAKEFILE	:= $(abspath $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)))
WORKING_DIR		:= $(dir $(THIS_MAKEFILE) )
PKG_DIR         := ./pkg
EXAMPLES_DIR    := ./examples
EXAMPLES_BIN    := ./bin
RESULTS_DIR     := ./tests/results

# For debugging
include setup.mk

# Variables
VERSION       ?= $(shell cat ./VERSION)
TYPE          ?= minimal
GOCMD         ?= go
GOTEST        ?=$(GOCMD) test
GOVET         ?=$(GOCMD) vet
GOOS          ?= linux
EXPORT_RESULT ?=false # for CI please set EXPORT_RESULT to true

# Library source
PKG_SRC := $(shell find $(PKG_DIR) -name \*.go -type f)

# Examples build support
EXAMPLE_SRC = $(shell find $(EXAMPLES_DIR) -name \*.go -type f)
EXAMPLE_APPS := $(patsubst ./examples/%/,%,$(sort $(dir $(wildcard ./examples/*/))))

# tool containers.  The ONF OpenSource project VOLTHA contains several containers
# that are useful for building and testing.  Look for the voltha-go or voltha-lib-go
# projects on https://github.com/opencord for any updates.  The initial format of this
# makefile was based on the voltha-go makefile from Fall 2022.

VOLTHA_TOOLS_VERSION ?= 2.4.0

GO                = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app $(shell test -t 0 && echo "-it") -v gocache:/.cache -v gocache-${VOLTHA_TOOLS_VERSION}:/go/pkg voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-golang go
GO_JUNIT_REPORT   = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app -i voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-go-junit-report go-junit-report
GOCOVER_COBERTURA = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app/src/github.com/opencord/voltha-openolt-adapter -i voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-gocover-cobertura gocover-cobertura
GOLANGCI_LINT     = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app $(shell test -t 0 && echo "-it") -v gocache:/.cache -v gocache-${VOLTHA_TOOLS_VERSION}:/go/pkg voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-golangci-lint golangci-lint

TARGETS := help build lint-mod lint-go lint test sca clan distclean mod-update examples
.PHONY: $(TARGET)
.DEFAULT_GOAL := help

## Default:
build: test examples ## Only a library project, so build target is unit tests and example applications

## Lint:
lint-mod: ## Verify the Go dependencies
	@echo "Running dependency check..."
	@${GO} mod verify
	@echo "Dependency check OK. Running vendor check..."
	@git status > /dev/null
	@git diff-index --quiet HEAD -- go.mod go.sum vendor || (echo "ERROR: Staged or modified files must be committed before running this test" && git status -- go.mod go.sum vendor && exit 1)
	@[[ `git ls-files --exclude-standard --others go.mod go.sum vendor` == "" ]] || (echo "ERROR: Untracked files must be cleaned up before running this test" && git status -- go.mod go.sum vendor && exit 1)
	${GO} mod tidy
	${GO} mod vendor
	@git status > /dev/null
	@git diff-index --quiet HEAD -- go.mod go.sum vendor || (echo "ERROR: Modified files detected after running go mod tidy / go mod vendor" && git status -- go.mod go.sum vendor && git checkout -- go.mod go.sum vendor && exit 1)
	@[[ `git ls-files --exclude-standard --others go.mod go.sum vendor` == "" ]] || (echo "ERROR: Untracked files detected after running go mod tidy / go mod vendor" && git status -- go.mod go.sum vendor && git checkout -- go.mod go.sum vendor && exit 1)
	@echo "Vendor check OK."

lint-go: ## Use golintci-lint on your project
	$(eval OUTPUT_OPTIONS = $(shell [ "${EXPORT_RESULT}" == "true" ] && echo "--out-format checkstyle ./... | tee /dev/tty > checkstyle-report.xml" || echo "" ))
	docker run --rm -v $(shell pwd):/app -w /app golangci/golangci-lint:latest-alpine golangci-lint run --deadline=65s $(OUTPUT_OPTIONS)

lint: lint-go  ## Run all lint targets

## Test:
test: ## Run unit tests
	@mkdir -p ./tests/results
	@${GO} test -mod=vendor -v -coverprofile ./tests/results/go-test-coverage.out -covermode count ./... 2>&1 | tee ./tests/results/go-test-results.out ;\
	RETURN=$$? ;\
	${GO_JUNIT_REPORT} < ./tests/results/go-test-results.out > ./tests/results/go-test-results.xml ;\
	${GOCOVER_COBERTURA} < ./tests/results/go-test-coverage.out > ./tests/results/go-test-coverage.xml ;\
	exit $$RETURN

sca: ## Runs static code analysis with the golangci-lint tool
	@rm -rf ./sca-report
	@mkdir -p ./sca-report
	@echo "Running static code analysis..."
	@${GOLANGCI_LINT} run --deadline=6m --out-format junit-xml ./... | tee ./sca-report/sca-report.xml
	@echo ""
	@echo "Static code analysis OK"

## Utility:
clean: ## Removes any local filesystem artifacts generated by a build
	rm -rf ${EXAMPLES_BIN}

distclean: clean ## Removes any local filesystem artifacts generated by a build or test run
	rm -rf ./sca-report ${RESULTS_DIR}

mod-update: ## Update go mod files
	${GO} mod tidy
	#${GO} mod vendor

fmt: ## Formats the source code to go best practice style
	@go fmt ${PACKAGES}

## Examples:
.PHONY: example-info
example-info:
	$(Q) echo "Library Sources : ${PKG_SRC}"
	$(Q) echo "Example Sources : ${EXAMPLE_SRC}"
	$(Q) echo "Example Apps    : ${EXAMPLE_APPS}"

$(EXAMPLES_BIN):
	$(Q) mkdir -p $(EXAMPLES_BIN)

examples: $(EXAMPLES_BIN) $(EXAMPLE_APPS)  ## Build example applications
$(EXAMPLE_APPS):
	$(Q) mkdir -p $(EXAMPLES_BIN)
	GOOS=$(GOOS) go build -o $(EXAMPLES_BIN)/$@ ./examples/$@
	$(Q) sudo setcap cap_net_raw=eip $(EXAMPLES_BIN)/$@

## Help:
help: ## Print help for each Makefile target
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target> [<target> ...]${RESET}'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} { \
		if (/^[a-zA-Z_-]+:.*?##.*$$/) {printf "    ${YELLOW}%-20s${GREEN}%s${RESET}\n", $$1, $$2} \
		else if (/^## .*$$/) {printf "  ${CYAN}%s${RESET}\n", substr($$1,4)} \
		}' $(MAKEFILE_LIST)
