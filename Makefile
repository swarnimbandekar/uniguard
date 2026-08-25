# =============================================================================
# Cyber Threat Detection Pipeline - Makefile
# =============================================================================

.PHONY: all setup train generate run stop clean test help

help: ## Show this help
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  setup       Install Python dependencies for training and traffic generation"
	@echo "  train       Train all ML models (DDoS, PortScan, DGA)"
	@echo "  generate    Generate demo PCAP traffic files"
	@echo "  run         Start the full pipeline with Docker Compose"
	@echo "  stop        Stop all services"
	@echo "  logs        View logs from all services"
	@echo "  test        Run integration tests"
	@echo "  clean       Remove generated files and containers"
	@echo ""

all: setup train generate run ## Full setup: install, train, generate traffic, start pipeline

# --- Setup ---
setup: ## Install Python dependencies
	pip install -r ml-service/requirements.txt
	pip install -r scripts/requirements.txt

# --- Training ---
train: ## Train ML models
	cd ml-service && python train.py

# --- Traffic Generation ---
generate: ## Generate demo PCAP files
	python scripts/generate_traffic.py --output data/pcaps

# --- Docker Commands ---
run: ## Start the full pipeline
	docker-compose up --build -d
	@echo ""
	@echo "==================================================="
	@echo " Pipeline is starting up..."
	@echo " Dashboard:  http://localhost:3000"
	@echo " API:        http://localhost:8000/api/health"
	@echo " Kafka:      localhost:9092"
	@echo " gRPC:       localhost:50051"
	@echo "==================================================="

stop: ## Stop all services
	docker-compose down

logs: ## View logs
	docker-compose logs -f

logs-ingest: ## View ingest service logs
	docker-compose logs -f ingest

logs-ml: ## View ML inference logs
	docker-compose logs -f ml-inference

logs-extractor: ## View feature extractor logs
	docker-compose logs -f feature-extractor

logs-backend: ## View backend logs
	docker-compose logs -f backend

# --- Testing ---
test: ## Run integration test
	python scripts/integration_test.py

# --- Cleanup ---
clean: ## Remove containers, volumes, and generated files
	docker-compose down -v --remove-orphans
	rm -rf ml-service/models/*.pkl
	rm -rf ml-service/models/*.json
	rm -rf data/pcaps/*.pcap
