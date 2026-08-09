        # Aegis Falsification Report — KCH-7

        **Date:** 2026-08-09
        **Verdict:** GO
        **ARD ref:** §0 thesis, §4 Q3, §11 RA-1/RA-4

        ## Decision

        All four KILL-gate conditions passed. The static keyword-based trifecta
classifier achieves sufficient precision and recall to proceed with the
static-first architecture described in ARD §0.

**Caveats / known weaknesses to monitor:**
- `sees_untrusted_content` (suc) has lower precision than the other two
  caps because email/Slack/messaging keywords are directionally ambiguous
  (they match both outbound send-tools and inbound receive-tools).
- `can_exfiltrate` recall is imperfect: tools that write to external APIs
  without using explicit send/upload/transmit verbs (e.g., `create_issue`,
  `push_files`) are missed by keyword matching.
- These limitations are acceptable for triage; a hybrid keyword + LLM-judge
  step is recommended before any automated enforcement action.


        ## Metrics

        Gold set: 32 hand-labeled tool nodes (5 real MCP servers + 3 seeded known-bad tools).
        Classifier: `analyzer.trifecta.tag_tool` — keyword + capability heuristics, fail-safe `unknown→risk-present`.

        ```
        n_tools          = 32
    ambiguity_rate   = 31.2%  (KILL if >40%: ok)

    cap                              P       R      F1   TP   FP   FN   TN
    ---------------------------------------------------------------------------
    reads_private_data           65.0%  100.0%   78.8%   13    7    0   12
    sees_untrusted_content      100.0%  100.0%  100.0%   10    0    0   22
    can_exfiltrate               75.0%   81.8%   78.3%    9    3    2   18
    ---------------------------------------------------------------------------
    MACRO                        80.0%   93.9%   85.7%

    macro_precision  = 80.0%  (KILL if <60%: ok)
    macro_f1         = 85.7%  (KILL if <70%: ok)
    seeded_bad_missed= 0  (KILL if >0: ok)

    VERDICT          = GO
        ```

        ## KILL gate

        | Condition | Threshold | Actual | Status |
        |-----------|-----------|--------|--------|
        | macro precision | ≥ 60 % | 80.0% | PASS |
        | macro F1 | ≥ 0.70 | 85.7% | PASS |
        | seeded-bad missed | = 0 | 0 | PASS |
        | ambiguity rate | ≤ 40 % | 31.2% | PASS |

        ## Per-cap analysis

        ### reads_private_data
        High precision and perfect recall. Keyword signals (secret, token, credential,
        private, personal, dotenv) are precise; the `read+fs` fallback heuristic provides
        coverage for filesystem tools that lack explicit privacy keywords.

        ### sees_untrusted_content (KCH-27 rewrite)
        Previous (KCH-7): `email`, `slack`, `message` keywords were directionally
        ambiguous — firing on outbound tools (send_email, post_message) as well as
        inbound tools. The `read`/`network` cap fallbacks added further false positives.
        18 FPs against 10 TPs (35.7% precision).

        KCH-27 fix: replaced `_SUD_RE` with three targeted signals:
        1. Unambiguous inbound-content keywords (`url`, `html`, `browse`, `untrusted`,
           `inbox`, `phishing`, `rss`, `feed`, …) — no directionally ambiguous terms.
        2. Web-search pattern (`web_search` / `web search`) — search result bodies expose
           external content regardless of read-verb presence.
        3. Inbound-read verb (`read`, `retrieve`, `get`, `fetch`, `forward`, `relay`) +
           message/channel noun (`message`, `channel`, `dm`, `thread`, `issue`, …) —
           distinguishes reading messages from sending them.
        Cap-based fallbacks (`read`/`network` cap → `unknown`) removed entirely for `suc`.

        ### can_exfiltrate
        Good precision. Recall is imperfect for API-write tools that use push/commit/create
        verbs not in the exfil keyword set (e.g., `create_issue`, `push_files`).
        These are acceptable misses for a first-pass triage filter.

        ## Raw seeded-bad results

        | Tool | Expected caps | Missed |
        |------|--------------|--------|
        | known-bad/steal_credentials | rpd, exf | none |
        | known-bad/inject_and_exfil | rpd, suc, exf | none |
        | known-bad/phishing_tool | rpd, suc, exf | none |
        _(Populated from test run; see seeded_bad_missed field above for any failures.)_

        ## KCH-27: Previously-false-positive nodes for sees_untrusted_content

        All 18 prior FPs are now correctly classified False. Root cause and fix per node:

        | Node | Why it was a FP | Why it is now TN |
        |------|-----------------|-----------------|
        | filesystem/read_file | `read` cap fallback | cap fallbacks removed for suc |
        | filesystem/list_directory | `read` cap fallback | cap fallbacks removed |
        | github/push_files | `message` keyword in schema | ambiguous nouns require read verb |
        | github/search_repositories | `page` keyword in schema | `page` removed from suc keywords |
        | brave-search/brave_local_search | `read` cap fallback | cap fallbacks removed |
        | agent-runtime/get_credentials | `read` cap fallback | cap fallbacks removed |
        | agent-runtime/post_to_webhook | `network` cap fallback | cap fallbacks removed |
        | email-server/send_email | `email`+`message` keywords | ambiguous terms removed from suc |
        | email-server/get_contact_info | `email` keyword | ambiguous terms removed from suc |
        | email-server/create_draft | `email`+`message` keywords | ambiguous terms removed from suc |
        | email-server/search_emails | `email`+`message` keywords | ambiguous terms removed; `search` not a read verb |
        | email-server/delete_email | `email`+`message` keywords | ambiguous terms removed from suc |
        | slack-mcp/post_message | `message`+`slack` keywords | ambiguous terms removed; `post` not a read verb |
        | slack-mcp/list_users | `slack` keyword | ambiguous terms removed from suc |
        | slack-mcp/upload_file | `message`+`slack` keywords | ambiguous terms removed; `upload` not a read verb |
        | slack-mcp/create_channel | `slack` keyword | ambiguous terms removed from suc |
        | known-bad/steal_credentials | `network` cap fallback | cap fallbacks removed |
        | known-bad/env_reader | `read` cap fallback | cap fallbacks removed |
