# Repository Visibility Strategy

## Current Status: Public Demo Repository

This repository currently serves as a **technical showcase** demonstrating:
- Security engineering capabilities
- System design thinking
- Production-ready code quality
- DevOps/deployment skills

## What's Public (Safe to Share)

✅ **Core Architecture**
- Middleware pattern and "Sandwich Model" security
- PII scrubbing implementation (Presidio)
- Chronicle integration
- IDOR detection (basic ownership-aware logic)
- Docker deployment setup

✅ **Technical Documentation**
- System design docs
- Integration guides
- Demo instructions
- Compliance overview (general)

✅ **Code Quality Indicators**
- Tests and coverage
- Linting/formatting
- Type hints and documentation
- Error handling

## What's Private (Competitive Advantage)

🔒 **Strategic Business Documents** (excluded via .gitignore)
- `STRATEGY_PRIVATE.md` - Comprehensive competitive analysis
- `COMPETITIVE_ANALYSIS.md` - Cloudflare vs. us positioning
- `ROADMAP_INTERNAL.md` - Detailed feature roadmap with implementation
- `PRICING.md` - Pricing strategy and ROI calculations
- `docs/private/` - Customer data, pilot results, sales materials

🔒 **Advanced Detection Logic** (implementation details)
- Mass assignment detection algorithms
- Synthetic identity detection ML models
- Transaction anomaly analysis (LLM prompts)
- Insider threat UEBA baselines
- Step-up authentication logic

🔒 **LLM Prompts** (core IP)
- Triage analysis prompts
- Financial crime detection prompts
- Synthetic identity analysis
- Context enrichment templates

## Post-Interview Options

### Option 1: Keep Public (Current State)
**Pros:**
- Demonstrates technical skills to other employers
- Open source contribution on resume
- Community feedback and contributions

**Cons:**
- Competitors can clone core architecture
- Limits ability to commercialize independently

**Recommendation:** Keep current public state if:
- You join the company and they want it public
- You want to showcase work for future job searches
- Core IP (advanced detections) stays private

### Option 2: Make Private
**Pros:**
- Protects competitive advantage
- Enables commercialization (startup, side project)
- Controls who sees advanced features

**Cons:**
- Can't showcase work publicly
- Harder to demonstrate skills to future employers
- No community contributions

**Recommendation:** Make private if:
- You want to spin this into a product
- Company IP concerns (if you join them)
- Building advanced features (Phase 2+)

### Option 3: Hybrid - Public Showcase + Private Development
**Pros:**
- Best of both worlds
- Public repo shows skills, private repo has IP
- Clean separation of concerns

**Cons:**
- Maintain two repos
- Need to be careful about what gets public

**Recommendation:** Create two repos:
- `llm-soc-triage` (public) - Current demo code, sanitized
- `agentic-security-platform` (private) - Full product, advanced features

**Structure:**
```
PUBLIC (llm-soc-triage):
- Basic IDOR detection
- Chronicle integration
- PII scrubbing demo
- Docker deployment
- General architecture docs

PRIVATE (agentic-security-platform):
- STRATEGY_PRIVATE.md
- Advanced detection modules (mass assignment, synthetic ID, etc.)
- Full LLM prompts
- Customer data and pilots
- Pricing and business strategy
```

## GitHub Settings After Interview

### If You Get The Job

```bash
# Option A: Archive public repo (read-only)
# Settings → General → Danger Zone → Archive this repository
# Keeps history public but frozen

# Option B: Make private
# Settings → General → Danger Zone → Change repository visibility → Private

# Option C: Transfer to company
# Settings → General → Danger Zone → Transfer ownership
# (Only if company requests it)
```

### If You Want to Commercialize

```bash
# 1. Create private org
gh org create agentic-security

# 2. Create private product repo
gh repo create agentic-security/platform --private

# 3. Copy advanced features to private repo
cp STRATEGY_PRIVATE.md ../agentic-security-platform/
cp -r core/advanced_detectors ../agentic-security-platform/core/

# 4. Keep public repo as sanitized demo
# (Current state is fine)
```

## Legal Considerations

### Patent Protection

If you plan to commercialize, consider:
- **Provisional Patent:** File before public disclosure (~$150)
- **Full Patent:** Within 12 months of provisional (~$10K)
- **Focus:** "Ownership-aware stateful attack detection with LLM reasoning"

**Prior Art Risk:** Public GitHub repo = public disclosure
- File provisional patent BEFORE making advanced features public
- Or keep advanced features private until patent filed

### Employment IP Assignment

**Important:** If you join a company:
- They may own IP you create during employment
- Check your employment agreement carefully
- IP created BEFORE employment = yours
- IP created AFTER = probably theirs

**Strategy:**
1. Build core IP (Phase 1) BEFORE joining → You own it
2. Offer to license/sell to employer
3. OR: Keep private and build on side (check employment agreement)

## Action Plan: Thursday → Friday

### Thursday Night (After Interview)

**If Interview Went Well:**
1. Keep repo public (shows confidence)
2. Commit DEMO_SUCCESS.md updates
3. Add polished README sections
4. DO NOT commit STRATEGY_PRIVATE.md

**If They Made Offer:**
1. Ask about IP policy in offer discussion
2. Decide on public/private strategy
3. File provisional patent if commercializing

### Friday (Day After)

**If Offer Accepted:**
```bash
# Make strategic docs private
git rm --cached STRATEGY_PRIVATE.md  # Remove from git but keep local
echo "*.PRIVATE.*" >> .gitignore
git add .gitignore
git commit -m "Update gitignore for private strategy docs"
git push
```

**If Still Interviewing Elsewhere:**
- Keep public to showcase work
- Continue committing non-sensitive updates
- Keep advanced features local only

## Current .gitignore Protection

Already excluded from git:
```
STRATEGY_PRIVATE.md
COMPETITIVE_ANALYSIS.md
ROADMAP_INTERNAL.md
PRICING.md
docs/private/
notes/
*_CONFIDENTIAL.md
customer_profiles/
pilot_data/
```

These files live on your local machine but won't be committed.

## Summary

**Right Now:**
- Public repo with basic IDOR detection ✅
- Private strategy docs (local only) ✅
- Professional showcase ✅

**After Thursday Interview:**
- Decide based on outcome
- Options: Keep public, make private, or hybrid
- Protect IP if commercializing

**Long Term:**
- Public repo = portfolio piece
- Private repo = product development
- Patent = commercial protection

---

## Questions to Ask Yourself

1. **Do I want to work for this company?**
   - Yes → Keep public until they request otherwise
   - No → Consider commercializing (make private)

2. **Do I want to build this as a product?**
   - Yes → Make private, file provisional patent
   - No → Keep public as portfolio piece

3. **Am I interviewing elsewhere?**
   - Yes → Keep public to showcase skills
   - No → Can make private safely

**Default Recommendation:** Keep public repo as-is (demo quality), keep advanced features local-only until you decide.
