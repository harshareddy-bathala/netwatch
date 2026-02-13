# Contributing to NetWatch

## Getting Started

1. Fork and clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/macOS
   venv\Scripts\activate      # Windows
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the test suite:
   ```bash
   pytest tests/ -v
   ```

## Project Structure

| Directory | Purpose |
|-----------|---------|
| `packet_capture/` | Packet sniffing, mode detection, bandwidth calculation |
| `packet_capture/modes/` | Network mode implementations (hotspot, wifi, etc.) |
| `database/` | SQLite connection pool, schema, query modules |
| `alerts/` | Alert engine, deduplication, anomaly detection |
| `backend/` | Flask API server and route definitions |
| `frontend/` | SPA dashboard (HTML/CSS/JS) |
| `tests/` | Pytest test suite |
| `deploy/` | Platform deployment scripts |
| `docs/` | Documentation |

## Development Guidelines

### Code Style
- Follow PEP 8
- Use type hints for function signatures
- Docstrings for all public classes and methods
- Maximum line length: 120 characters

### Testing
- Write tests for all new features
- Tests go in `tests/` using pytest
- Run the full suite before opening a PR:
  ```bash
  pytest tests/ -v --tb=short
  ```
- Performance tests: `pytest tests/test_performance.py -v`

### Branching
- `main` — stable, production-ready
- `dev` — active development
- Feature branches: `feature/<description>`
- Bug fixes: `fix/<description>`

### Commit Messages
Use conventional commits:
```
feat: add port mirror mode detection
fix: resolve database lock under concurrent writes
docs: update API reference for /api/bandwidth/dual
test: add integration tests for mode changes
```

### Pull Requests
1. Create a feature branch from `dev`
2. Make your changes with tests
3. Ensure `pytest tests/ -v` passes
4. Open a PR targeting `dev`
5. Describe the change and link any related issues

## Architecture Notes

- **Modes** extend `BaseMode` (ABC) in `packet_capture/modes/`
- **Database** uses SQLite WAL with a connection pool — never hold connections long
- **Alerts** flow through `AlertEngine` → `AlertDeduplicator` → database
- **API** is Flask, served from `backend/app.py` with routes in `backend/routes.py`
- **Frontend** is a vanilla JS SPA — no build step required

## Running Locally

Admin/root privileges are required for packet capture (Scapy needs raw sockets).

```bash
# Windows (Run as Administrator)
python main.py

# Linux
sudo python main.py

# With options
python main.py --port 8080 --log-level DEBUG --no-capture
```

## Questions?

Open an issue or check [docs/](docs/) for detailed guides.
