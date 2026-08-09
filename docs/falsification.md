        # Aegis Falsification Report — KCH-7

        **Date:** 2026-08-09
        **Verdict:** PIVOT
        **ARD ref:** §0 thesis, §4 Q3, §11 RA-1/RA-4

        ## Decision

                  One or more KILL-gate conditions failed. The static keyword-based classifier
          does NOT meet the precision/recall bar set in ARD §4 Q3. Recommended pivot:

          **Option A — Hybrid LLM judge:** Keep keyword pass as a pre-filter, add an
          LLM-judge step that re-evaluates ambiguous and low-confidence tags.

          **Option B — Data-flow / runtime tracing:** Instrument the MCP transport
          layer to observe actual data flows rather than relying on descriptions.

          Kill reasons:
            - macro precision 58.6% < 60% threshold
- macro F1 69.9% < 70% threshold
- ambiguity rate 43.8% > 40% threshold


        ## Metrics

        Gold set: 32 hand-labeled tool nodes (5 real MCP servers + 3 seeded known-bad tools).
        Classifier: `analyzer.trifecta.tag_tool` — keyword + capability heuristics, fail-safe `unknown→risk-present`.

        ```
        n_tools          = 32
    ambiguity_rate   = 43.8%  (KILL if >40%: TRIGGERED)

    cap                              P       R      F1   TP   FP   FN   TN
    ---------------------------------------------------------------------------
    reads_private_data           65.0%  100.0%   78.8%   13    7    0   12
    sees_untrusted_content       35.7%  100.0%   52.6%   10   18    0    4
    can_exfiltrate               75.0%   81.8%   78.3%    9    3    2   18
    ---------------------------------------------------------------------------
    MACRO                        58.6%   93.9%   69.9%

    macro_precision  = 58.6%  (KILL if <60%: TRIGGERED)
    macro_f1         = 69.9%  (KILL if <70%: TRIGGERED)
    seeded_bad_missed= 0  (KILL if >0: ok)

    VERDICT          = KILL / PIVOT
        ```

        ## KILL gate

        | Condition | Threshold | Actual | Status |
        |-----------|-----------|--------|--------|
        | macro precision | ≥ 60 % | 58.6% | FAIL |
        | macro F1 | ≥ 0.70 | 69.9% | FAIL |
        | seeded-bad missed | = 0 | 0 | PASS |
        | ambiguity rate | ≤ 40 % | 43.8% | FAIL |

        ## Per-cap analysis

        ### reads_private_data
        High precision and perfect recall. Keyword signals (secret, token, credential,
        private, personal, dotenv) are precise; the `read+fs` fallback heuristic provides
        coverage for filesystem tools that lack explicit privacy keywords.

        ### sees_untrusted_content
        Lower precision: email/Slack/messaging keywords (`email`, `slack`, `message`)
        are directionally ambiguous — they fire on outbound tools (send_email, post_message)
        as well as inbound tools (read_inbox, read_channel). The `read`-cap fallback also
        creates false positives for internal-only readers.
        Recall is perfect because the fail-safe `unknown` path catches all network-touching tools.

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
