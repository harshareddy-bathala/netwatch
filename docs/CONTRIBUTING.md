# Contributing to NetWatch

This document provides guidelines for team members contributing to the NetWatch project.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Git Workflow](#git-workflow)
3. [Branch Naming](#branch-naming)
4. [Commit Messages](#commit-messages)
5. [Pull Request Process](#pull-request-process)
6. [Code Style](#code-style)
7. [Testing](#testing)
8. [Documentation](#documentation)
9. [Code Review](#code-review)
10. [AI Usage Guidelines](#ai-usage-guidelines)

---

## Code of Conduct

As team members, we agree to:

- **Respect:** Treat all team members with respect
- **Collaborate:** Help each other succeed
- **Communicate:** Keep the team informed of progress and blockers
- **Quality:** Write code we're proud of
- **Learn:** Be open to feedback and improvement

---

## Git Workflow

We use a feature branch workflow:

```
main (protected)
 └── feature/your-feature
 └── bugfix/bug-description
 └── hotfix/urgent-fix
```

### Basic Workflow

1. Pull latest main:
   ```bash
   git checkout main
   git pull origin main
   ```

2. Create feature branch:
   ```bash
   git checkout -b feature/add-bandwidth-chart
   ```

3. Make changes and commit:
   ```bash
   git add .
   git commit -m "feat: add bandwidth history chart"
   ```

4. Push to remote:
   ```bash
   git push origin feature/add-bandwidth-chart
   ```

5. Create Pull Request on GitHub

6. After approval, merge to main

### Syncing Your Branch

Keep your branch updated with main:
```bash
git checkout feature/your-feature
git fetch origin
git rebase origin/main
```

---

## Branch Naming

Use descriptive branch names with prefixes:

| Prefix | Use Case | Example |
|--------|----------|---------|
| `feature/` | New features | `feature/add-alerts-api` |
| `bugfix/` | Bug fixes | `bugfix/fix-null-pointer` |
| `hotfix/` | Urgent fixes | `hotfix/security-patch` |
| `docs/` | Documentation | `docs/update-api-docs` |
| `refactor/` | Code refactoring | `refactor/cleanup-db-handler` |

**Format:** `prefix/short-description`

**Examples:**
- ✅ `feature/add-device-search`
- ✅ `bugfix/fix-chart-rendering`
- ❌ `my-changes`
- ❌ `fix`

---

## Commit Messages

We use conventional commits format:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `style` | Formatting (no code change) |
| `refactor` | Code restructuring |
| `test` | Adding tests |
| `chore` | Maintenance tasks |

### Scopes

| Scope | Module |
|-------|--------|
| `backend` | Flask API |
| `frontend` | Dashboard |
| `capture` | Packet capture |
| `db` | Database |
| `alerts` | Anomaly detection |

### Examples

```bash
# Good commits
git commit -m "feat(backend): add GET /api/alerts endpoint"
git commit -m "fix(frontend): fix chart not updating on refresh"
git commit -m "docs: update API documentation for new endpoints"

# Bad commits
git commit -m "fixed stuff"
git commit -m "changes"
git commit -m "WIP"
```

---

## Pull Request Process

### Before Creating a PR

1. ✅ Code works locally
2. ✅ No console errors or warnings
3. ✅ Code follows style guidelines
4. ✅ Branch is up to date with main
5. ✅ Self-review completed

### Creating a PR

1. Go to GitHub repository
2. Click "New Pull Request"
3. Select your branch
4. Fill out the PR template:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tested locally
- [ ] Tested API endpoints with curl/browser
- [ ] Tested frontend in browser

## Checklist
- [ ] Code follows project style
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated if needed
```

### After Creating a PR

1. Request review from Project Lead (Member 1)
2. Address any feedback
3. Wait for approval
4. Merge once approved (squash merge preferred)

---

## Code Style

### Python (Backend)

Follow PEP 8 guidelines:

```python
# Good
def get_top_devices(limit: int = 10, hours: int = 1) -> list:
    """Get top N devices by bandwidth in the last X hours.
    
    Args:
        limit: Maximum number of devices to return
        hours: Time window in hours
    
    Returns:
        List of device dictionaries
    """
    pass

# Bad
def getTopDevices(limit,hours):
    pass
```

**Key Points:**
- 4 spaces for indentation
- Snake_case for functions and variables
- PascalCase for classes
- Type hints encouraged
- Docstrings for all public functions

### JavaScript (Frontend)

```javascript
// Good
async function getRealtimeStats() {
    try {
        const response = await fetch('/api/stats/realtime');
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Failed to fetch stats:', error);
        return null;
    }
}

// Bad
function get_realtime_stats() {
    return fetch('/api/stats/realtime').then(r => r.json())
}
```

**Key Points:**
- 4 spaces for indentation
- camelCase for functions and variables
- PascalCase for classes
- Always use `const` or `let`, never `var`
- Use async/await over .then() chains

### HTML/CSS

```html
<!-- Good -->
<div class="metric-card" id="bandwidth-card">
    <h3 class="card-title">Bandwidth</h3>
    <p class="card-value" id="bandwidth-value">0 MB/s</p>
</div>

<!-- Bad -->
<DIV CLASS="metricCard" ID="bandwidthCard">
<h3>Bandwidth</h3>
<p id=bandwidth-value>0 MB/s</p></DIV>
```

**Key Points:**
- Lowercase tags and attributes
- Quote attribute values
- Use semantic HTML
- Indent nested elements
- BEM naming for CSS classes

---

## Testing

### Manual Testing

Before submitting code:

1. **Backend:** Test API endpoints
   ```bash
   # Test status endpoint
   curl http://localhost:5000/api/status
   
   # Test with parameters
   curl "http://localhost:5000/api/devices/top?limit=5"
   ```

2. **Frontend:** Open in browser and verify:
   - Page loads without errors
   - Data displays correctly
   - Charts render properly
   - Responsive on different sizes

3. **Integration:** Start full application and verify:
   - Packet capture works
   - Data appears in dashboard
   - Updates every 3 seconds

### Testing Checklist

- [ ] Happy path works
- [ ] Error cases handled
- [ ] Edge cases considered (empty data, null values)
- [ ] Console is clean (no errors/warnings)

---

## Documentation

### When to Update Docs

Update documentation when you:
- Add a new API endpoint
- Change function signatures
- Add new features
- Fix bugs that affect usage

### Where to Update

| Change | Update |
|--------|--------|
| New API endpoint | `docs/API_DOCS.md` |
| Architecture change | `docs/ARCHITECTURE.md` |
| Setup changes | `docs/SETUP_GUIDE.md` |
| New user features | `docs/USER_MANUAL.md` |

### Documentation Style

- Use clear, simple language
- Include code examples
- Keep formatting consistent
- Update table of contents

---

## Code Review

### As an Author

- Keep PRs focused (one feature/fix per PR)
- Write clear PR descriptions
- Respond to feedback constructively
- Make requested changes promptly

### As a Reviewer

- Be constructive and helpful
- Explain the "why" behind suggestions
- Approve when satisfied
- Use these labels:
  - **Comment:** Just a thought
  - **Suggestion:** Consider changing
  - **Request:** Must change before merge

### Review Focus Areas

1. **Correctness:** Does it work?
2. **Clarity:** Is it readable?
3. **Consistency:** Does it match existing style?
4. **Completeness:** Are edge cases handled?
5. **Documentation:** Are changes documented?

---

## AI Usage Guidelines

We encourage using AI assistants (like Claude Opus 4.5) to improve productivity:

### Recommended Uses

✅ **Do use AI for:**
- Understanding error messages
- Writing boilerplate code
- Generating documentation
- Debugging issues
- Learning new concepts
- Code review suggestions

### Usage Best Practices

1. **Be specific** in your prompts:
   ```
   # Good prompt
   "Write a Flask route that queries the database for the top 10 
   devices by bandwidth and returns JSON"
   
   # Bad prompt
   "Write the API"
   ```

2. **Review AI output:**
   - Always read generated code
   - Test before committing
   - Understand what the code does

3. **Provide context:**
   - Share relevant existing code
   - Explain the project structure
   - Mention constraints

4. **Iterate:**
   - Refine prompts based on output
   - Ask follow-up questions
   - Request explanations

### Example Prompts by Role

**Backend Developer:**
```
"I need a Flask route at GET /api/protocols that:
1. Accepts optional 'hours' query parameter (default 1)
2. Calls get_protocol_distribution(hours) from db_handler
3. Returns JSON with 'protocols' array
4. Handles errors gracefully"
```

**Frontend Developer:**
```
"Write JavaScript to:
1. Fetch data from /api/bandwidth/history
2. Update a Chart.js line chart
3. Format timestamps as HH:MM
4. Handle fetch errors with retry logic"
```

---

## Questions?

If you have questions about contributing:
1. Check this document first
2. Ask the Project Lead (Member 1)
3. Discuss in team meetings
