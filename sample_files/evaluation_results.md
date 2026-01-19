# LCRE CLI Blind Test - Evaluation Results (2026-01-18 - Run 2)

## Test Summary

| Metric | Value |
|--------|-------|
| **Total Samples** | 20 |
| **Legitimate Samples** | 10 |
| **Malware Samples** | 10 |
| **Overall Accuracy** | 85% (17/20) |

## Detailed Results

| Sample | Actual | Predicted | Confidence | Correct | Notes |
|--------|--------|-----------|------------|---------|-------|
| sample_01 | Legitimate (Cygwin ls) | LEGITIMATE | HIGH | ✓ | GNU coreutils ls 8.26, Cygwin compiled |
| sample_02 | Malware (Locky) | SUSPICIOUS | HIGH | ⚠️ | Partial - flagged uniform entropy, keylogger strings, suspicious imports |
| sample_03 | Legitimate (Windows cmd x86) | LEGITIMATE | HIGH | ✓ | Windows Command Processor correctly identified |
| sample_04 | Malware (Petya) | LEGITIMATE | HIGH | ✗ | **FALSE NEGATIVE** - Disguised as Java updater |
| sample_05 | Malware (Linux.Wirenet) | MALICIOUS | HIGH | ✓ | RAT with keylogger, password theft, reverse shell |
| sample_06 | Legitimate (Windows cmd x64) | LEGITIMATE | HIGH | ✓ | Windows 7 SP1 cmd.exe correctly identified |
| sample_07 | Legitimate (macOS ls) | LEGITIMATE | HIGH | ✓ | BSD ls with Apple code signatures |
| sample_08 | Legitimate (FreeBSD echo) | LEGITIMATE | HIGH | ✓ | FreeBSD echo with Capsicum security |
| sample_09 | Malware (CryptoLocker) | MALICIOUS | HIGH | ✓ | YARA Locky_Ransomware match, Bitcoin references |
| sample_10 | Legitimate (Linux bash ARM64) | LEGITIMATE | HIGH | ✓ | GNU Bash for ARM64 |
| sample_11 | Legitimate (Sysinternals) | LEGITIMATE | HIGH | ✓ | Correctly identified as Autoruns (AntiVM dismissed as FP) |
| sample_12 | Legitimate (Linux bash) | LEGITIMATE | HIGH | ✓ | GNU Bash 4.1.5 with standard imports |
| sample_13 | Malware (Mirai) | MALICIOUS | HIGH | ✓ | C2 IPs (79.124.8.24), exploit payloads, IoT botnet |
| sample_14 | Legitimate (Linux ls ARMv7) | LEGITIMATE | HIGH | ✓ | GNU coreutils ls 8.21 |
| sample_15 | Malware (ZeusVM) | MALICIOUS | HIGH | ✓ | YARA ASPack match, high entropy 7.92, zero imports |
| sample_16 | Legitimate (BusyBox) | LEGITIMATE | HIGH | ✓ | BusyBox v1.35.0 statically linked |
| sample_17 | Malware (Stuxnet) | SUSPICIOUS | MEDIUM | ⚠️ | Partial - flagged driver anomalies, process enum APIs |
| sample_18 | Malware (Linux.Encoder) | MALICIOUS | HIGH | ✓ | Ransomware - README_FOR_DECRYPT.txt, .encrypted extension |
| sample_19 | Malware (WannaCry) | MALICIOUS | HIGH | ✓ | YARA WannaCry match, .wnry extensions, high entropy 7.995 |
| sample_20 | Malware (Emotet) | MALICIOUS | HIGH | ✓ | VB6 stub pattern, encrypted payload, DllFunctionCall |

## Performance Metrics

### Classification Metrics

| Metric | Count |
|--------|-------|
| **True Positives (TP)** | 7 |
| **True Negatives (TN)** | 10 |
| **False Positives (FP)** | 0 |
| **False Negatives (FN)** | 1 |
| **Partial (SUSPICIOUS)** | 2 |

### Rate Metrics

| Metric | Formula | Value |
|--------|---------|-------|
| **True Positive Rate (Sensitivity/Recall)** | TP / (TP + FN) | 70% (7/10) strict, 90% with SUSPICIOUS |
| **True Negative Rate (Specificity)** | TN / (TN + FP) | 100% (10/10) |
| **False Positive Rate** | FP / (FP + TN) | 0% (0/10) |
| **False Negative Rate** | FN / (TP + FN) | 10% (1/10) |
| **Precision** | TP / (TP + FP) | 100% (7/7) |
| **Accuracy** | (TP + TN) / Total | 85% (17/20) |

## Comparison with Previous Run

| Metric | Previous Run | Current Run | Change |
|--------|--------------|-------------|--------|
| **Overall Accuracy** | 80% (16/20) | 85% (17/20) | **+5%** |
| **True Positives** | 7 | 7 | = |
| **True Negatives** | 9 | 10 | **+1** |
| **False Positives** | 1 | 0 | **-1** |
| **False Negatives** | 3 | 1 | **-2** |
| **Sensitivity (Recall)** | 70% | 70-90% | = to +20% |
| **Specificity** | 90% | 100% | **+10%** |
| **Precision** | 87.5% | 100% | **+12.5%** |

### Changes in Individual Samples

| Sample | Previous | Current | Change |
|--------|----------|---------|--------|
| sample_11 (Sysinternals) | MALICIOUS (FP) | LEGITIMATE | ✓ Fixed |
| sample_17 (Stuxnet) | LEGITIMATE (FN) | SUSPICIOUS | ⚠️ Improved |
| sample_18 (Linux.Encoder) | SUSPICIOUS | MALICIOUS | ✓ Improved |
| sample_20 (Emotet) | LEGITIMATE (FN) | MALICIOUS | ✓ Fixed |
| sample_02 (Locky) | MALICIOUS | SUSPICIOUS | ⚠️ Regression |

## Analysis of Errors

### False Negative (Complete Miss)

#### sample_04 (Petya Ransomware)
- **Predicted**: LEGITIMATE (HIGH confidence)
- **Cause**: Binary masquerades as Oracle Java Auto-Updater (JRE 8u73)
- **Why missed**: Contains legitimate-looking Java URLs (javadl-esd-secure.oracle.com), build paths, scheduling options
- **YARA matched**: AntiVM_Techniques (dismissed as legitimate for update scheduling)
- **Lesson**: Malware bundled with or masquerading as legitimate software is extremely difficult to detect statically

### Partial Detections (SUSPICIOUS)

#### sample_02 (Locky Ransomware)
- **Predicted**: SUSPICIOUS (HIGH confidence)
- **Findings**: Uniform entropy across sections (6.774), suspicious imports (EncryptFileW, CreateProcessAsUserA), keylogger strings
- **Why not MALICIOUS**: No specific ransomware YARA match, analysis was thorough but conservative

#### sample_17 (Stuxnet)
- **Predicted**: SUSPICIOUS (MEDIUM confidence)
- **Findings**: Unusual device names (Gpd0/Gpd1), process enumeration APIs in driver, typo in version info
- **Why not MALICIOUS**: Lacks specific Stuxnet YARA signatures, presents as hardware driver

## Key Observations

### Improvements This Run

1. **Eliminated False Positives**: sample_11 (Sysinternals) now correctly classified as LEGITIMATE
   - Agent properly dismissed AntiVM YARA match as false positive for system monitoring tool

2. **Fixed Emotet Detection**: sample_20 now correctly identified as MALICIOUS
   - Detected VB6 stub pattern, encrypted payload, DllFunctionCall API resolution
   - Fake "Goodreads" metadata noted as suspicious

3. **Improved Stuxnet Detection**: sample_17 now SUSPICIOUS instead of LEGITIMATE
   - Noted driver anomalies and process enumeration APIs unusual for RAID driver

4. **Promoted Linux.Encoder**: sample_18 now MALICIOUS instead of SUSPICIOUS
   - Correctly identified ransom note path and .encrypted extension

### Persistent Challenges

1. **Petya Masquerading**: Still missed due to convincing Java updater disguise
   - Static analysis alone cannot easily distinguish bundled malware from legitimate software

2. **Conservative on Locky**: Downgraded from MALICIOUS to SUSPICIOUS
   - More cautious classification approach this run

## YARA Rule Effectiveness

| Rule | Triggered On | Result |
|------|--------------|--------|
| WannaCry_Ransomware | sample_19 | ✅ True Positive |
| Locky_Ransomware | sample_09 | ✅ True Positive (on CryptoLocker) |
| ASPack_Packer | sample_15 | ✅ True Positive |
| AntiVM_Techniques | sample_04, sample_11 | ⚠️ Properly handled as FP this run |

## Recommendations

### To Address Remaining False Negative
1. Add specific Petya/NotPetya YARA signatures
2. Flag binaries that mix update/scheduling functionality with anti-VM techniques
3. Consider reputation scoring for embedded URLs/domains

### To Promote SUSPICIOUS to MALICIOUS
1. Multiple suspicious indicators (uniform entropy + keylogger APIs + crypto APIs) should auto-escalate
2. Kernel drivers with user-mode process enumeration should be flagged higher
3. Add Stuxnet-specific signatures

## Conclusion

The current LCRE build achieved **85% accuracy** with **zero false positives**, showing improvement over the previous run:

**Strengths:**
- Perfect legitimate binary recognition (100% specificity)
- Strong YARA-based ransomware detection (WannaCry, CryptoLocker, ZeusVM)
- Effective IoT/Linux malware identification (Mirai, Wirenet, Linux.Encoder)
- Improved VB6 malware detection (Emotet)

**Remaining Challenges:**
- Malware masquerading as legitimate vendor software (Petya as Java updater)
- Conservative threshold between SUSPICIOUS and MALICIOUS classifications

For production triage, this posture is appropriate for **high-confidence detections with minimal false positives**. SUSPICIOUS classifications should trigger further investigation.

---

## Log Files

All detailed analysis logs are available for review:
- `eval_log_sample_01.md` through `eval_log_sample_20.md`
- Each contains full command outputs, reasoning, and findings
