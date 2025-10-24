import { useState } from "react";
import { Card } from "./ui/card";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Button } from "./ui/button";
import { Alert, AlertDescription } from "./ui/alert";
import { Search, Copy, CheckCircle2, Loader2, XCircle, AlertTriangle, Shield, Mail, FileText } from "lucide-react";
import { toast } from "sonner";

interface DNSRecord {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DNSResponse {
  Status: number;
  Answer?: DNSRecord[];
}

interface AnalysisResult {
  spf: {
    exists: boolean;
    records: string[];
    analysis: Array<{
      record: string;
      index: number;
      hasMoosend: boolean;
      isMoosendOnly: boolean;
    }>;
    hasMoosend: boolean;
    hasMultiple: boolean;
    errors: string[];
    warnings: string[];
  };
  dkim: {
    exists: boolean;
    record: string | null;
    isCNAME: boolean;
    cnameTarget: string | null;
    isDuplicated: boolean;
    duplicatedLocation: string | null;
    errors: string[];
  };
  dmarc: {
    exists: boolean;
    record: string | null;
    records: string[];
    hasMultiple: boolean;
    policy: string | null;
    errors: string[];
  };
}

export function DNSLookup() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [requestId, setRequestId] = useState<number>(0);

  const lookupDNS = async (queryDomain: string, recordType: string = "TXT"): Promise<DNSRecord[]> => {
    try {
      // Using Google DNS-over-HTTPS API (supports CORS for browser requests)
      const response = await fetch(
        `https://dns.google.com/resolve?name=${encodeURIComponent(queryDomain)}&type=${recordType}`
      );
      const data: DNSResponse = await response.json();

      if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
        return data.Answer;
      }
      return [];
    } catch (err) {
      console.error('DNS lookup error:', err);
      return [];
    }
  };

  const analyzeDomain = async () => {
    if (!domain.trim()) {
      setError("Please enter a domain name");
      return;
    }

    // Prevent concurrent requests
    if (loading) {
      return;
    }

    // Generate a unique request ID to handle race conditions
    const currentRequestId = Date.now();
    setRequestId(currentRequestId);
    
    setLoading(true);
    setError(null);
    setAnalysis(null);

    try {
      const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');

      // Check SPF
      const spfRecords = await lookupDNS(cleanDomain, "TXT");
      const spfResults = spfRecords
        .map(r => r.data.replace(/^"|"$/g, ''))
        .filter(data => data.startsWith('v=spf1'));

      // Analyze each SPF record for Moosend authorization
      const spfAnalysis = spfResults.map((spf, index) => ({
        record: spf,
        index: index + 1,
        hasMoosend: spf.includes('include:spfa.mailendo.com'),
        isMoosendOnly: !!spf.match(/^v=spf1\s+include:spfa\.mailendo\.com\s+[~\-?+]all$/),
      }));

      const hasMoosend = spfAnalysis.some(spf => spf.hasMoosend);
      const hasMultipleSPF = spfResults.length > 1;
      const spfErrors: string[] = [];
      const spfWarnings: string[] = [];

      if (hasMultipleSPF) {
        spfErrors.push(`Multiple SPF records detected (${spfResults.length} records). Only one SPF record is allowed per domain. This invalidates all SPF records.`);
      }

      // Check for SPF syntax - ensure it has a terminator (~all, -all, ?all, +all)
      if (spfResults.length === 1) {
        const spf = spfResults[0];
        const hasTerminator = /[~\-?+]all/.test(spf);

        if (!hasTerminator) {
          spfWarnings.push(`SPF record is missing a terminator (like ~all or -all). We recommend adding "~all" at the end for soft fail protection.`);
        } else if (!spf.includes('~all')) {
          const currentTerminator = spf.match(/([~\-?+]all)/)?.[1];
          spfWarnings.push(`SPF uses "${currentTerminator}" terminator. While this works, we recommend "~all" as it's safer for most use cases.`);
        }
      }

      // Check for too many DNS lookups (improved mechanism detection)
      if (spfResults.length === 1) {
        const spf = spfResults[0];

        // Count includes
        const includeCount = (spf.match(/include:[^\s]+/g) || []).length;

        // Count 'a' mechanisms (including a:domain.com)
        const aCount = (spf.match(/\sa(?::|[\s~\-?+]|$)/g) || []).length;

        // Count 'mx' mechanisms (including mx:domain.com)
        const mxCount = (spf.match(/\smx(?::|[\s~\-?+]|$)/g) || []).length;

        // Count 'ptr' mechanisms (not recommended but counts as lookup)
        const ptrCount = (spf.match(/\sptr(?::|[\s~\-?+]|$)/g) || []).length;

        // Count 'exists' mechanisms
        const existsCount = (spf.match(/exists:[^\s]+/g) || []).length;

        const totalLookups = includeCount + aCount + mxCount + ptrCount + existsCount;

        if (totalLookups > 8) {
          spfWarnings.push(`High DNS lookup count detected (${totalLookups} total lookups: ${includeCount} includes, ${aCount} a, ${mxCount} mx${ptrCount > 0 ? `, ${ptrCount} ptr` : ''}${existsCount > 0 ? `, ${existsCount} exists` : ''}). SPF has a 10 lookup limit. Some includes may contain nested lookups, so this could go over. If the customer needs to add more services, consider SPF flattening.`);
        } else if (totalLookups > 5) {
          spfWarnings.push(`Moderate DNS lookup count (${totalLookups} lookups). Still within the limit of 10, but keep in mind that some includes may have nested lookups. Monitor if adding more services.`);
        }
      }

      // Check DKIM - ms._domainkey
      const dkimDomain = `ms._domainkey.${cleanDomain}`;
      const dkimRecords = await lookupDNS(dkimDomain, "TXT");
      
      // Filter for actual TXT records (type 16) that contain Moosend DKIM key data
      let dkimData = null;
      let isCNAME = false;
      let cnameTarget = null;
      
      if (dkimRecords.length > 0) {
        // First, check if there's a TXT record with actual DKIM data
        const txtRecords = dkimRecords.filter(r => r.type === 16);
        if (txtRecords.length > 0) {
          const recordData = txtRecords[0].data.replace(/^"|"$/g, '');
          // Check if it looks like a DKIM key (contains v=DKIM1 or p=)
          if (recordData.includes('v=DKIM1') || recordData.includes('p=')) {
            dkimData = recordData;
          }
        }
        
        // If no direct TXT record, check for CNAME
        if (!dkimData) {
          const cnameRecords = dkimRecords.filter(r => r.type === 5);
          if (cnameRecords.length > 0) {
            isCNAME = true;
            cnameTarget = cnameRecords[0].data.replace(/\.$/, ''); // Remove trailing dot
            
            // Check if CNAME points to a known third-party provider (not Moosend)
            const isThirdPartyProvider = cnameTarget.includes('sendgrid') || 
                                        cnameTarget.includes('mailgun') || 
                                        cnameTarget.includes('mailchimp') ||
                                        cnameTarget.includes('sparkpost') ||
                                        cnameTarget.includes('amazonses');
            
            if (isThirdPartyProvider) {
              // Don't resolve - this is not Moosend's DKIM
              dkimData = null;
            } else {
              // Try to fetch the actual DKIM key from the CNAME target
              try {
                const targetRecords = await lookupDNS(cnameTarget, "TXT");
                if (targetRecords.length > 0) {
                  const txtRecords = targetRecords.filter(r => r.type === 16);
                  if (txtRecords.length > 0) {
                    const targetData = txtRecords[0].data.replace(/^"|"$/g, '');
                    if (targetData.includes('v=DKIM1') || targetData.includes('p=')) {
                      dkimData = targetData;
                    }
                  }
                }
              } catch (err) {
                console.error('Error resolving CNAME target:', err);
              }
            }
          }
        }
      }

      let isDuplicated = false;
      let duplicatedLocation = null;
      let dkimErrors: string[] = [];

      // If no DKIM found, check for domain duplication or third-party DKIM
      if (!dkimData) {
        // Check if there's a CNAME to a third-party provider
        if (isCNAME && cnameTarget) {
          const isThirdPartyProvider = cnameTarget.includes('sendgrid') || 
                                      cnameTarget.includes('mailgun') || 
                                      cnameTarget.includes('mailchimp') ||
                                      cnameTarget.includes('sparkpost') ||
                                      cnameTarget.includes('amazonses');
          
          if (isThirdPartyProvider) {
            const providerName = cnameTarget.includes('sendgrid') ? 'SendGrid' :
                                cnameTarget.includes('mailgun') ? 'Mailgun' :
                                cnameTarget.includes('mailchimp') ? 'Mailchimp' :
                                cnameTarget.includes('sparkpost') ? 'SparkPost' :
                                cnameTarget.includes('amazonses') ? 'Amazon SES' : 'another provider';
            
            dkimErrors.push(`DKIM selector "ms._domainkey" is currently configured for ${providerName} (CNAME: ${cnameTarget}). To use Moosend, the customer needs to update this DKIM record with the values from their Moosend dashboard.`);
          } else {
            dkimErrors.push(`No Moosend DKIM record found. The selector "ms._domainkey" has a CNAME to ${cnameTarget}, but it doesn't appear to be configured correctly.`);
          }
        } else {
          // Check for domain duplication
          const duplicatedDomain = `ms._domainkey.${cleanDomain}.${cleanDomain}`;
          const duplicatedRecords = await lookupDNS(duplicatedDomain, "TXT");

          if (duplicatedRecords.length > 0) {
            isDuplicated = true;
            duplicatedLocation = duplicatedDomain;
            dkimErrors.push(`DKIM record found at wrong location: ${duplicatedDomain}. The DNS manager auto-appended the domain. Delete the record and recreate using only "ms._domainkey" as the host value.`);
          } else {
            dkimErrors.push(`No DKIM record found for selector "ms._domainkey". If you recently added it, wait 5-30 minutes for DNS propagation.`);
          }
        }
      }

      // Check DMARC
      const dmarcDomain = `_dmarc.${cleanDomain}`;
      const dmarcRecords = await lookupDNS(dmarcDomain, "TXT");
      const dmarcResults = dmarcRecords
        .map(r => r.data.replace(/^"|"$/g, ''))
        .filter(data => data.startsWith('v=DMARC1'));
      
      const hasMultipleDMARC = dmarcResults.length > 1;
      const dmarcData = dmarcResults.length > 0 ? dmarcResults[0] : null;
      const dmarcErrors: string[] = [];

      if (hasMultipleDMARC) {
        dmarcErrors.push(`Multiple DMARC records detected (${dmarcResults.length} records). Only one DMARC record is allowed per domain. This invalidates all DMARC records.`);
      }

      let dmarcPolicy = null;
      if (dmarcData && !hasMultipleDMARC) {
        const policyMatch = dmarcData.match(/p=([^;]+)/);
        dmarcPolicy = policyMatch ? policyMatch[1] : null;
      } else if (!dmarcData) {
        dmarcErrors.push("No DMARC record found. DMARC is recommended for complete email authentication.");
      }

      // Check if this is still the current request (prevent race conditions)
      if (currentRequestId === requestId) {
        setAnalysis({
          spf: {
            exists: spfResults.length > 0,
            records: spfResults,
            analysis: spfAnalysis,
            hasMoosend,
            hasMultiple: hasMultipleSPF,
            errors: spfErrors,
            warnings: spfWarnings,
          },
          dkim: {
            exists: !!dkimData,
            record: dkimData,
            isCNAME,
            cnameTarget,
            isDuplicated,
            duplicatedLocation,
            errors: dkimErrors,
          },
          dmarc: {
            exists: dmarcResults.length > 0,
            record: dmarcData,
            records: dmarcResults,
            hasMultiple: hasMultipleDMARC,
            policy: dmarcPolicy,
            errors: dmarcErrors,
          },
        });
      }
    } catch (err) {
      // Only set error if this is still the current request
      if (currentRequestId === requestId) {
        setError("Failed to perform DNS lookup. Please try again.");
        setAnalysis(null);
      }
    } finally {
      // Only set loading to false if this is still the current request
      if (currentRequestId === requestId) {
        setLoading(false);
      }
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

  const generateFullReport = () => {
    if (!analysis) return "";

    let report = `=== EMAIL AUTHENTICATION ANALYSIS ===\n`;
    report += `Domain: ${domain}\n`;
    report += `Analyzed: ${new Date().toLocaleString()}\n\n`;

    // SPF Section
    report += `--- SPF RECORDS ---\n`;
    if (analysis.spf.exists) {
      report += `Status: ${analysis.spf.errors.length > 0 ? '❌ Issues Found' : '✓ Found'}\n`;
      report += `Records Found: ${analysis.spf.records.length}\n`;

      if (analysis.spf.hasMultiple) {
        report += `\n⚠️ CRITICAL: Multiple SPF records detected (only 1 allowed per domain)\n`;
        report += `This invalidates ALL SPF records.\n\n`;
        
        report += `All SPF Records Found:\n`;
        analysis.spf.analysis.forEach((spfInfo) => {
          report += `  Record ${spfInfo.index}: ${spfInfo.record}\n`;
          if (spfInfo.hasMoosend && spfInfo.isMoosendOnly) {
            report += `    └─ Analysis: Moosend Only (likely incomplete)\n`;
          } else if (spfInfo.hasMoosend) {
            report += `    └─ Analysis: Contains Moosend + other services (GOOD)\n`;
          } else {
            report += `    └─ Analysis: No Moosend authorization\n`;
          }
        });

        // Intelligent recommendation
        const recordsWithMoosend = analysis.spf.analysis.filter(s => s.hasMoosend && !s.isMoosendOnly);
        if (recordsWithMoosend.length > 0) {
          const bestRecord = recordsWithMoosend[0];
          report += `\n💡 RECOMMENDED ACTION:\n`;
          report += `  Keep: SPF Record ${bestRecord.index} (has all services + Moosend)\n`;
          report += `  Delete: All other SPF records\n`;
          report += `  Reason: This record preserves existing services while adding Moosend authorization\n`;
        } else {
          report += `\n💡 RECOMMENDED ACTION:\n`;
          report += `  Merge records manually - no single record contains both existing services and Moosend\n`;
        }
      } else {
        report += `\nCurrent SPF Record:\n`;
        report += `  ${analysis.spf.records[0]}\n`;
        
        if (analysis.spf.hasMoosend) {
          report += `\nMoosend Authorization: ✓ Authorized (include:spfa.mailendo.com present)\n`;
        } else {
          report += `\nMoosend Authorization: ❌ NOT authorized (missing include:spfa.mailendo.com)\n`;
          report += `Action: Add "include:spfa.mailendo.com" to the existing SPF record\n`;
          const currentSpf = analysis.spf.records[0];
          const updatedSpf = currentSpf.replace(/~all|-all|\?all|\+all/g, 'include:spfa.mailendo.com $&');
          report += `\nRecommended Updated Record:\n  ${updatedSpf}\n`;
        }
      }

      if (analysis.spf.errors.length > 0) {
        report += `\nErrors:\n`;
        analysis.spf.errors.forEach((err: string) => report += `  • ${err}\n`);
      }

      if (analysis.spf.warnings.length > 0) {
        report += `\nWarnings:\n`;
        analysis.spf.warnings.forEach((warn: string) => report += `  • ${warn}\n`);
      }
    } else {
      report += `Status: ❌ Not Found\n`;
      report += `Action: Customer needs to add an SPF record with Moosend authorization.\n`;
      report += `Recommended value: v=spf1 include:spfa.mailendo.com ~all\n`;
    }

    // DKIM Section
    report += `\n--- DKIM RECORDS (Moosend Selector: ms._domainkey) ---\n`;
    if (analysis.dkim.exists) {
      report += `Status: ✓ Found\n`;
      report += `Location: ms._domainkey.${domain}\n`;
      if (analysis.dkim.isCNAME && analysis.dkim.cnameTarget) {
        report += `Configuration: CNAME (points to ${analysis.dkim.cnameTarget})\n`;
      }
      report += `DKIM Public Key: ${analysis.dkim.record}\n`;
    } else {
      if (analysis.dkim.isDuplicated) {
        report += `Status: ❌ Domain Duplication Issue\n`;
        report += `Checked ms._domainkey.${domain} - No record found\n`;
        report += `Tested ms._domainkey.${domain}.${domain} - Record found\n\n`;
        report += `Issue: DNS manager auto-appended the domain name.\n`;
        report += `Fix: Edit the DKIM record's host field and change it to just "ms._domainkey" (remove the domain portion)\n`;
      } else {
        report += `Status: ❌ Not Found\n`;
        report += `Checked: ms._domainkey.${domain}\n`;
        report += `Action: Customer needs to add DKIM record from Moosend dashboard.\n`;
        report += `Note: DNS propagation can take 5-30 minutes.\n`;
      }
    }

    // DMARC Section
    report += `\n--- DMARC RECORDS ---\n`;
    if (analysis.dmarc.hasMultiple) {
      report += `Status: ❌ CRITICAL - Multiple DMARC Records (Invalid Configuration)\n`;
      report += `Records Found: ${analysis.dmarc.records.length}\n\n`;
      report += `Issue: Only ONE DMARC record is allowed per domain. Multiple records invalidate the entire DMARC configuration.\n\n`;
      report += `Current DMARC Records:\n`;
      analysis.dmarc.records.forEach((rec: string, idx: number) => {
        const policyMatch = rec.match(/p=([^;]+)/);
        const policy = policyMatch ? policyMatch[1] : 'unknown';
        report += `  Record ${idx + 1} (Policy: ${policy}): ${rec}\n`;
      });
      report += `\nAction Required:\n`;
      report += `  1. Review both DMARC records above\n`;
      report += `  2. Choose which policy best fits customer needs\n`;
      report += `  3. Delete ONE of the DMARC records from DNS manager\n`;
      report += `  4. Keep only the DMARC record with preferred policy\n`;
      report += `Note: We don't recommend a specific record - customer should consult deliverability team if unsure.\n`;
    } else if (analysis.dmarc.exists) {
      report += `Status: ✓ Found\n`;
      if (analysis.dmarc.policy) {
        report += `Policy: p=${analysis.dmarc.policy}\n`;
      }
      report += `Record: ${analysis.dmarc.record}\n`;
    } else {
      report += `Status: ❌ Not Found (Highly Recommended)\n`;
      report += `Note: All major ISPs now require DMARC for senders sending 5,000+ emails.\n`;
      report += `Action: Customer should add DMARC for better deliverability and security.\n`;
      report += `Recommended starter record:\n`;
      report += `  Host: _dmarc\n`;
      report += `  Value: v=DMARC1; p=none;\n`;
      report += `Note: Start with p=none to monitor. Can make stricter later.\n`;
    }

    report += `\n=== END OF REPORT ===\n`;
    return report;
  };

  const copyFullReport = () => {
    const report = generateFullReport();
    navigator.clipboard.writeText(report);
    toast.success("Full report copied to clipboard!");
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-white mb-2">DNS Lookup Tool</h2>
        <p className="text-white/70">
          Automatically analyze email authentication records and detect common configuration issues.
        </p>
      </div>

      <Card className="bg-white/10 backdrop-blur-xl border-white/20 p-6">
        <div className="space-y-4">
          <div>
            <Label className="text-white mb-2 block">Domain</Label>
            <Input
              value={domain}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
                setDomain(e.target.value);
                // Clear previous results when user changes domain
                if (analysis) {
                  setAnalysis(null);
                  setError(null);
                }
              }}
              onKeyPress={(e: React.KeyboardEvent<HTMLInputElement>) => e.key === "Enter" && analyzeDomain()}
              placeholder="example.com"
              className="bg-white/10 border-white/20 text-white placeholder:text-white/40"
            />
          </div>

          <Button
            onClick={analyzeDomain}
            disabled={loading}
            className="w-full bg-blue-500/30 border border-blue-400/50 text-white hover:bg-blue-500/40"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Search className="h-4 w-4 mr-2" />
                Analyze Email Authentication
              </>
            )}
          </Button>

          {error && (
            <Alert className="bg-amber-500/10 backdrop-blur-xl border-amber-500/30">
              <AlertDescription className="text-white/90">{error}</AlertDescription>
            </Alert>
          )}

          {analysis && (
            <div className="space-y-6 mt-6">
              {/* Copy Full Report Button */}
              <Button
                onClick={copyFullReport}
                variant="outline"
                className="w-full bg-green-500/20 border border-green-400/50 text-white hover:bg-green-500/30"
              >
                <FileText className="h-4 w-4 mr-2" />
                Copy Full Report (for tickets/emails)
              </Button>

              {/* SPF Analysis */}
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <Shield className="h-6 w-6 text-blue-400" />
                  <h3 className="text-white">SPF Records</h3>
                </div>

                {analysis.spf.exists ? (
                  <div className="space-y-3">
                    <Alert className={`${analysis.spf.errors.length > 0 ? 'bg-red-500/10 border-red-500/30' : 'bg-green-500/10 border-green-500/30'} backdrop-blur-xl`}>
                      {analysis.spf.errors.length > 0 ? (
                        <XCircle className="h-5 w-5 text-red-400" />
                      ) : (
                        <CheckCircle2 className="h-5 w-5 text-green-400" />
                      )}
                      <AlertDescription className="text-white/90">
                        {analysis.spf.errors.length > 0 ? (
                          <span className="text-red-300">SPF Configuration Issues Detected</span>
                        ) : (
                          <span className="text-green-300">SPF Record Found</span>
                        )}
                      </AlertDescription>
                    </Alert>

                    {/* Display all SPF records */}
                    {analysis.spf.hasMultiple ? (
                      <div className="space-y-3">
                        <div className="bg-amber-500/10 backdrop-blur-sm p-3 rounded border border-amber-400/30">
                          <p className="text-sm text-white mb-2">
                            <strong>All SPF Records Found:</strong> ({analysis.spf.records.length} records - Only 1 allowed)
                          </p>
                        </div>
                        
                        {analysis.spf.analysis.map((spfInfo, idx) => (
                          <Card key={idx} className="bg-white/5 backdrop-blur-sm border-white/10 p-4">
                            <div className="space-y-2">
                              <div className="flex items-start justify-between gap-2 mb-2">
                                <span className="text-white/80 text-sm font-semibold">SPF Record #{spfInfo.index}</span>
                                <div className="flex gap-2">
                                  {spfInfo.hasMoosend && (
                                    <span className="text-xs bg-green-500/20 text-green-300 px-2 py-1 rounded">Has Moosend</span>
                                  )}
                                  {spfInfo.isMoosendOnly && (
                                    <span className="text-xs bg-blue-500/20 text-blue-300 px-2 py-1 rounded">Moosend Only</span>
                                  )}
                                  {!spfInfo.hasMoosend && (
                                    <span className="text-xs bg-amber-500/20 text-amber-300 px-2 py-1 rounded">No Moosend</span>
                                  )}
                                </div>
                              </div>
                              <div className="bg-black/30 backdrop-blur-sm p-3 rounded border border-white/10 break-all">
                                <code className="text-blue-200 text-sm">{spfInfo.record}</code>
                              </div>
                              <Button
                                onClick={() => copyToClipboard(spfInfo.record)}
                                variant="ghost"
                                size="sm"
                                className="text-white/60 hover:text-white hover:bg-white/5 w-full"
                              >
                                <Copy className="h-4 w-4 mr-2" />
                                Copy Record #{spfInfo.index}
                              </Button>
                            </div>
                          </Card>
                        ))}
                        
                        {/* Intelligent recommendation */}
                        <Alert className="bg-blue-500/10 backdrop-blur-xl border-blue-500/30">
                          <CheckCircle2 className="h-5 w-5 text-blue-400" />
                          <AlertDescription className="text-white/90">
                            <span className="text-blue-300 block mb-3 font-semibold">💡 Intelligent Recommendation</span>
                            {(() => {
                              const moosendOnlyRecords = analysis.spf.analysis.filter(s => s.isMoosendOnly);
                              const recordsWithMoosend = analysis.spf.analysis.filter(s => s.hasMoosend && !s.isMoosendOnly);
                              const recordsWithoutMoosend = analysis.spf.analysis.filter(s => !s.hasMoosend);

                              if (recordsWithMoosend.length > 0) {
                                const bestRecord = recordsWithMoosend[0];
                                return (
                                  <div>
                                    <p className="text-sm text-white mb-2">
                                      <strong>Recommended Action:</strong> Keep SPF Record #{bestRecord.index} and delete the others.
                                    </p>
                                    <div className="bg-green-500/10 backdrop-blur-sm p-3 rounded border border-green-400/30 mb-3">
                                      <p className="text-sm text-green-300 mb-2">✅ Keep This Record (has all services + Moosend):</p>
                                      <code className="text-green-200 text-sm break-all">{bestRecord.record}</code>
                                    </div>
                                    <p className="text-sm text-white/80">
                                      <strong>Why:</strong> This record contains both existing services and Moosend authorization, ensuring no email services will break.
                                    </p>
                                    {moosendOnlyRecords.length > 0 && (
                                      <p className="text-sm text-white/70 mt-2">
                                        Records #{moosendOnlyRecords.map(r => r.index).join(', ')} contain only Moosend and should be deleted.
                                      </p>
                                    )}
                                    {recordsWithoutMoosend.length > 0 && (
                                      <p className="text-sm text-white/70 mt-1">
                                        Records #{recordsWithoutMoosend.map(r => r.index).join(', ')} lack Moosend authorization and should be deleted.
                                      </p>
                                    )}
                                  </div>
                                );
                              } else {
                                return (
                                  <div>
                                    <p className="text-sm text-white mb-2">
                                      <strong>Action Required:</strong> No complete record found. You need to merge the records.
                                    </p>
                                    <p className="text-sm text-white/70 mb-2">
                                      Take the most complete SPF record and add <code className="bg-white/10 px-1 rounded">include:spfa.mailendo.com</code> to it.
                                    </p>
                                  </div>
                                );
                              }
                            })()}
                          </AlertDescription>
                        </Alert>
                      </div>
                    ) : (
                      <>
                        {/* Single record display */}
                        <Card className="bg-white/5 backdrop-blur-sm border-white/10 p-4">
                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="text-white/60 text-sm">Current SPF Record</span>
                              <div className="flex gap-2">
                                {analysis.spf.hasMoosend ? (
                                  <span className="text-xs bg-green-500/20 text-green-300 px-2 py-1 rounded">✓ Has Moosend</span>
                                ) : (
                                  <span className="text-xs bg-amber-500/20 text-amber-300 px-2 py-1 rounded">⚠ No Moosend</span>
                                )}
                                <Button
                                  onClick={() => copyToClipboard(analysis.spf.records[0])}
                                  variant="ghost"
                                  size="sm"
                                  className="text-white/60 hover:text-white hover:bg-white/5"
                                >
                                  <Copy className="h-4 w-4" />
                                </Button>
                              </div>
                            </div>
                            <div className="bg-black/30 backdrop-blur-sm p-3 rounded border border-white/10 break-all">
                              <code className="text-blue-200 text-sm">{analysis.spf.records[0]}</code>
                            </div>
                          </div>
                        </Card>

                        {!analysis.spf.hasMoosend && (
                          <Alert className="bg-amber-500/10 backdrop-blur-xl border-amber-500/30">
                            <AlertTriangle className="h-5 w-5 text-amber-400" />
                            <AlertDescription className="text-white/90">
                              <span className="text-amber-300 block mb-2">Moosend is not authorized in SPF record</span>
                              <p className="text-sm text-white/70 mb-2">
                                The customer needs to add <code className="bg-white/10 px-1 rounded text-blue-200">include:spfa.mailendo.com</code> to their existing SPF record.
                              </p>
                              <p className="text-sm text-white/70 mb-2">
                                <strong>Recommended Updated Record:</strong>
                              </p>
                              <div className="bg-green-500/10 backdrop-blur-sm p-2 rounded border border-green-400/30 break-all">
                                <code className="text-green-200 text-sm">
                                  {analysis.spf.records[0].replace(/~all|-all|\?all|\+all/g, 'include:spfa.mailendo.com $&')}
                                </code>
                              </div>
                            </AlertDescription>
                          </Alert>
                        )}

                        {analysis.spf.hasMoosend && (
                          <Alert className="bg-green-500/10 backdrop-blur-xl border-green-500/30">
                            <CheckCircle2 className="h-5 w-5 text-green-400" />
                            <AlertDescription className="text-white/90">
                              <span className="text-green-300">✓ Moosend is properly authorized</span>
                              <p className="text-sm text-white/70 mt-1">
                                <code className="bg-white/10 px-2 py-1 rounded text-blue-200">include:spfa.mailendo.com</code> is present
                              </p>
                            </AlertDescription>
                          </Alert>
                        )}
                      </>
                    )}

                    {/* Errors */}
                    {analysis.spf.errors.map((error: string, idx: number) => (
                      <Alert key={idx} className="bg-red-500/10 backdrop-blur-xl border-red-500/30">
                        <XCircle className="h-5 w-5 text-red-400" />
                        <AlertDescription className="text-white/90">
                          <span className="text-red-300 block mb-2 font-semibold">⚠️ Critical Issue: Multiple SPF Records Found!</span>
                          <span className="text-sm block mb-2">{error}</span>
                          {analysis.spf.hasMultiple && (
                            <>
                              <p className="text-sm mt-3 mb-2">Current SPF Records (ALL are being rejected):</p>
                              {analysis.spf.records.map((rec: string, recIdx: number) => (
                                <div key={recIdx} className="bg-black/30 backdrop-blur-sm p-2 rounded border border-white/10 break-all mb-2">
                                  <code className="text-red-200 text-sm">❌ Record {recIdx + 1}: {rec}</code>
                                </div>
                              ))}
                              <p className="text-sm mt-3 mb-2 text-white">
                                <strong>How to fix:</strong> Combine all includes into ONE record
                              </p>
                              <div className="bg-green-500/10 backdrop-blur-sm p-2 rounded border border-green-400/30 break-all">
                                <code className="text-green-200 text-sm">
                                  ✅ Combined: v=spf1 {analysis.spf.records.map((r: string) => {
                                    const includes = r.match(/include:[^\s]+/g) || [];
                                    const mechanisms = r.match(/\s(?:a|mx|ip4:[^\s]+|ip6:[^\s]+)/g) || [];
                                    return [...includes, ...mechanisms].join(' ');
                                  }).filter(Boolean).join(' ')} ~all
                                </code>
                              </div>
                            </>
                          )}
                        </AlertDescription>
                      </Alert>
                    ))}

                    {/* Warnings */}
                    {analysis.spf.warnings.map((warning: string, idx: number) => (
                      <Alert key={idx} className="bg-amber-500/10 backdrop-blur-xl border-amber-500/30">
                        <AlertTriangle className="h-5 w-5 text-amber-400" />
                        <AlertDescription className="text-white/90">
                          <span className="text-amber-300 block mb-1">Warning:</span>
                          <span className="text-sm block mb-2">{warning}</span>
                          {warning.includes('lookup') && (
                            <p className="text-xs text-blue-300 mt-2">
                              💡 If not comfortable resolving, escalate to Deliverability team.
                            </p>
                          )}
                        </AlertDescription>
                      </Alert>
                    ))}
                  </div>
                ) : (
                  <Alert className="bg-red-500/10 backdrop-blur-xl border-red-500/30">
                    <XCircle className="h-5 w-5 text-red-400" />
                    <AlertDescription className="text-white/90">
                      <span className="text-red-300">No SPF record found</span>
                      <p className="text-sm text-white/70 mt-1">
                        Add an SPF record to authorize email senders for this domain.
                      </p>
                    </AlertDescription>
                  </Alert>
                )}
              </div>

              {/* DKIM Analysis */}
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <Shield className="h-6 w-6 text-blue-400" />
                  <h3 className="text-white">DKIM Records (Moosend Selector: ms._domainkey)</h3>
                </div>

                {analysis.dkim.exists ? (
                  <div className="space-y-3">
                    <Alert className="bg-green-500/10 backdrop-blur-xl border-green-500/30">
                      <CheckCircle2 className="h-5 w-5 text-green-400" />
                      <AlertDescription className="text-white/90">
                        <span className="text-green-300">✓ Moosend DKIM record found</span>
                        <p className="text-sm text-white/70 mt-1">
                          Located at: <code className="bg-white/10 px-2 py-1 rounded text-blue-200">ms._domainkey.{domain}</code>
                        </p>
                        {analysis.dkim.isCNAME && analysis.dkim.cnameTarget && (
                          <p className="text-sm text-blue-300 mt-2">
                            ℹ️ Configured as CNAME pointing to: <code className="bg-white/10 px-2 py-1 rounded text-blue-200">{analysis.dkim.cnameTarget}</code>
                          </p>
                        )}
                      </AlertDescription>
                    </Alert>

                    <Card className="bg-white/5 backdrop-blur-sm border-white/10 p-4">
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-white/60 text-sm">DKIM Public Key</span>
                          <Button
                            onClick={() => copyToClipboard(analysis.dkim.record!)}
                            variant="ghost"
                            size="sm"
                            className="text-white/60 hover:text-white hover:bg-white/5"
                          >
                            <Copy className="h-4 w-4" />
                          </Button>
                        </div>
                        <div className="bg-black/30 backdrop-blur-sm p-3 rounded border border-white/10 break-all">
                          <code className="text-blue-200 text-sm">{analysis.dkim.record}</code>
                        </div>
                      </div>
                    </Card>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {analysis.dkim.isDuplicated ? (
                      <Alert className="bg-red-500/10 backdrop-blur-xl border-red-500/30 border-2">
                        <XCircle className="h-5 w-5 text-red-400" />
                        <AlertDescription className="text-white/90">
                          <span className="text-red-300 block mb-3 font-semibold">⚠️ DNS Manager Domain Duplication Issue</span>

                          <div className="space-y-2 text-sm mb-3">
                            <p className="text-white/80">
                              <span className="text-red-300">✗</span> Checked: <code className="bg-white/10 px-2 py-1 rounded">ms._domainkey.{domain}</code> - No record found
                            </p>
                            <p className="text-white/80">
                              <span className="text-green-300">✓</span> Tested: <code className="bg-white/10 px-2 py-1 rounded text-red-200">{analysis.dkim.duplicatedLocation}</code> - Record found
                            </p>
                          </div>

                          <div className="bg-blue-500/10 backdrop-blur-sm p-3 rounded border border-blue-400/30 mb-3">
                            <p className="text-sm text-white mb-2">
                              <strong>What happened:</strong> The DNS manager auto-appended the domain name when you entered the host.
                            </p>
                          </div>

                          <p className="text-sm text-white mb-2">
                            <strong>How to fix (2 simple steps):</strong>
                          </p>
                          <ol className="text-sm text-white/80 space-y-1 ml-4 list-decimal">
                            <li>Edit the DKIM record's host/name field</li>
                            <li>Change it from <code className="bg-red-500/20 px-1 rounded">ms._domainkey.{domain}</code> to just <code className="bg-green-500/20 px-1 rounded">ms._domainkey</code></li>
                          </ol>
                          <p className="text-xs text-white/60 mt-2">
                            Note: Most DNS managers (GoDaddy, Namecheap, etc.) automatically append the domain name, so you only need to enter the selector.
                          </p>
                        </AlertDescription>
                      </Alert>
                    ) : (
                      <Alert className="bg-amber-500/10 backdrop-blur-xl border-amber-500/30">
                        <AlertTriangle className="h-5 w-5 text-amber-400" />
                        <AlertDescription className="text-white/90">
                          <span className="text-amber-300">No DKIM record found for selector "ms._domainkey"</span>
                          <p className="text-sm text-white/70 mt-1">
                            Checked: <code className="bg-white/10 px-2 py-1 rounded text-blue-200">ms._domainkey.{domain}</code>
                          </p>
                          <p className="text-sm text-white/70 mt-2">
                            If you recently added it, wait 5-30 minutes for DNS propagation. If the issue persists, verify the host value in your DNS manager.
                          </p>
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                )}
              </div>

              {/* DMARC Analysis */}
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <Mail className="h-6 w-6 text-blue-400" />
                  <h3 className="text-white">DMARC Records</h3>
                </div>

                {analysis.dmarc.hasMultiple ? (
                  <div className="space-y-3">
                    <Alert className="bg-red-500/10 backdrop-blur-xl border-red-500/30 border-2">
                      <XCircle className="h-5 w-5 text-red-400" />
                      <AlertDescription className="text-white/90">
                        <span className="text-red-300 block mb-3 font-semibold">⚠️ Multiple DMARC Records Detected - Configuration Invalid</span>

                        <div className="bg-amber-500/10 backdrop-blur-sm p-3 rounded border border-amber-400/30 mb-3">
                          <p className="text-sm text-white mb-2">
                            <strong>Critical Issue:</strong> {analysis.dmarc.records.length} unique DMARC records found. Only ONE DMARC record is allowed per domain.
                          </p>
                          <p className="text-sm text-white/70">
                            Having multiple DMARC records invalidates your entire DMARC configuration. Email receivers will ignore all DMARC policies.
                          </p>
                        </div>

                        <p className="text-sm text-white mb-2">
                          <strong>Current DMARC Records Found:</strong>
                        </p>
                        <div className="space-y-2 mb-3">
                          {analysis.dmarc.records.map((rec: string, idx: number) => {
                            const policyMatch = rec.match(/p=([^;]+)/);
                            const policy = policyMatch ? policyMatch[1] : 'unknown';
                            return (
                              <div key={idx} className="bg-black/30 backdrop-blur-sm p-3 rounded border border-white/10">
                                <div className="flex items-start justify-between gap-2 mb-1">
                                  <span className="text-red-300 text-xs font-semibold">Record {idx + 1}</span>
                                  <span className="text-amber-300 text-xs">Policy: {policy}</span>
                                </div>
                                <code className="text-blue-200 text-xs break-all">{rec}</code>
                              </div>
                            );
                          })}
                        </div>

                        <div className="bg-blue-500/10 backdrop-blur-sm p-3 rounded border border-blue-400/30">
                          <p className="text-sm text-white mb-2">
                            <strong>How to fix:</strong>
                          </p>
                          <ol className="text-sm text-white/80 space-y-1 ml-4 list-decimal">
                            <li>Review both DMARC records above</li>
                            <li>Choose which policy best fits your needs (p=none for monitoring, p=quarantine or p=reject for enforcement)</li>
                            <li>Delete ONE of the DMARC records from your DNS manager</li>
                            <li>Keep only the DMARC record with your preferred policy</li>
                          </ol>
                          <p className="text-xs text-white/60 mt-2">
                            Note: We don't recommend a specific record since the choice depends on your email authentication strategy. If unsure, consult with your deliverability team.
                          </p>
                        </div>
                      </AlertDescription>
                    </Alert>
                  </div>
                ) : analysis.dmarc.exists ? (
                  <div className="space-y-3">
                    <Alert className="bg-green-500/10 backdrop-blur-xl border-green-500/30">
                      <CheckCircle2 className="h-5 w-5 text-green-400" />
                      <AlertDescription className="text-white/90">
                        <span className="text-green-300">✓ DMARC record found</span>
                        {analysis.dmarc.policy && (
                          <p className="text-sm text-white/70 mt-1">
                            Policy: <code className="bg-white/10 px-2 py-1 rounded text-blue-200">p={analysis.dmarc.policy}</code>
                          </p>
                        )}
                      </AlertDescription>
                    </Alert>

                    <Card className="bg-white/5 backdrop-blur-sm border-white/10 p-4">
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-white/60 text-sm">DMARC Record</span>
                          <Button
                            onClick={() => copyToClipboard(analysis.dmarc.record!)}
                            variant="ghost"
                            size="sm"
                            className="text-white/60 hover:text-white hover:bg-white/5"
                          >
                            <Copy className="h-4 w-4" />
                          </Button>
                        </div>
                        <div className="bg-black/30 backdrop-blur-sm p-3 rounded border border-white/10 break-all">
                          <code className="text-blue-200 text-sm">{analysis.dmarc.record}</code>
                        </div>
                      </div>
                    </Card>
                  </div>
                ) : (
                  <Alert className="bg-amber-500/10 backdrop-blur-xl border-amber-500/30">
                    <AlertTriangle className="h-5 w-5 text-amber-400" />
                    <AlertDescription className="text-white/90">
                      <span className="text-amber-300 block mb-2">No DMARC record found (Highly Recommended)</span>

                      <div className="bg-blue-500/10 backdrop-blur-sm p-3 rounded border border-blue-400/30 mb-3">
                        <p className="text-sm text-white mb-1">
                          <strong>Important:</strong> All major ISPs (Gmail, Yahoo, etc.) now require DMARC for senders sending 5,000+ emails.
                        </p>
                        <p className="text-sm text-white/70">
                          DMARC is highly advisable for better deliverability and security.
                        </p>
                      </div>

                      <p className="text-sm text-white mb-2">
                        <strong>Recommended Starter DMARC Record:</strong>
                      </p>
                      <div className="space-y-1 text-sm mb-2">
                        <p className="text-white/70">Host: <code className="bg-white/10 px-2 py-1 rounded text-blue-200">_dmarc</code></p>
                        <p className="text-white/70">Value: <code className="bg-white/10 px-2 py-1 rounded text-blue-200">v=DMARC1; p=none;</code></p>
                      </div>
                      <p className="text-xs text-white/60 mt-2">
                        Note: Start with p=none to monitor only. This won't reject emails. The record should end with a semicolon (;).
                      </p>
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </div>
          )}
        </div>
      </Card>

      <Card className="bg-blue-500/10 backdrop-blur-xl border-blue-400/30 p-6">
        <h4 className="text-white mb-3">What This Tool Checks:</h4>
        <div className="space-y-2 text-sm text-white/80">
          <div className="flex items-start gap-2">
            <span className="text-white/60">•</span>
            <span>SPF record existence and Moosend authorization (include:spfa.mailendo.com)</span>
          </div>
          <div className="flex items-start gap-2">
            <span className="text-white/60">•</span>
            <span>Multiple SPF records (causes validation failure)</span>
          </div>
          <div className="flex items-start gap-2">
            <span className="text-white/60">•</span>
            <span>SPF syntax validation (checks for proper terminator like ~all)</span>
          </div>
          <div className="flex items-start gap-2">
            <span className="text-white/60">•</span>
            <span>SPF DNS lookup count (warns if approaching the 10 lookup limit)</span>
          </div>
          <div className="flex items-start gap-2">
            <span className="text-white/60">•</span>
            <span>DKIM record for Moosend selector (ms._domainkey)</span>
          </div>
          <div className="flex items-start gap-2">
            <span className="text-white/60">•</span>
            <span>DNS manager domain duplication issues</span>
          </div>
          <div className="flex items-start gap-2">
            <span className="text-white/60">•</span>
            <span>DMARC record and policy configuration</span>
          </div>
        </div>

        <div className="mt-4 pt-4 border-t border-white/10">
          <p className="text-sm text-white/70">
            💡 <strong>Tip:</strong> Use the "Copy Full Report" button to easily paste analysis results into support tickets or customer emails.
          </p>
        </div>
      </Card>
    </div>
  );
}
