IMAGE_NAME := kbitcode
KERNEL_VERSION ?= 6.12.14
KERNEL_CONFIG ?= defconfig

.PHONY: help build test clean shell

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*##"}; {printf "  %-12s %s\n", $$1, $$2}'

build: ## Build the Docker image (kernel + kbitcode)
	docker build \
		--build-arg KERNEL_VERSION=$(KERNEL_VERSION) \
		--build-arg KERNEL_CONFIG=$(KERNEL_CONFIG) \
		-t $(IMAGE_NAME) .

test: ## Run kbitcode against the kernel build tree
	docker run --rm \
		-v "$$(pwd)/output:/output" \
		$(IMAGE_NAME)

clean: ## Remove the Docker image
	docker rmi $(IMAGE_NAME) 2>/dev/null || true

shell: ## Open an interactive shell in the container
	docker run --rm -it \
		-v "$$(pwd)/output:/output" \
		$(IMAGE_NAME) /bin/bash
