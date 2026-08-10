REPO=blacktop
NAME=go-macho
NEXT_VERSION:=$(shell svu patch)

.PHONY: dev-deps
dev-deps: ## Install the dev dependencies
	@go install github.com/caarlos0/svu@v1.12.0
	@go install golang.org/x/tools/cmd/goimports@v0.45.0

.PHONY: bump
bump: ## Tag and push the next patch version
	@echo " > Tagging ${NEXT_VERSION}"
	@git tag -a ${NEXT_VERSION} -m "Release ${NEXT_VERSION}"
	@git push origin ${NEXT_VERSION}

.PHONY: fmt
fmt: ## Format code
	@echo " > Formatting code"
	@gofmt -w -r 'interface{} -> any' .
	@goimports -w .
	@gofmt -w -s .
	@go mod tidy
	@go fix ./...

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
