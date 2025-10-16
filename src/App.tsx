import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";
import { CourseSection, ContentCard, MistakeAlert, CodeBlock } from "./components/CourseSection";
import { DNSLab } from "./components/DNSLab";
import { DNSLookup } from "./components/DNSLookup";
import { Navigation } from "./components/Navigation";
import { Mail, Shield, CheckCircle, AlertTriangle, Clock, Search as SearchIcon } from "lucide-react";
import { Toaster } from "./components/ui/sonner";

export default function App() {
  const [activeSection, setActiveSection] = useState("intro");
  const [activeAuthTab, setActiveAuthTab] = useState("spf");

  const handleNavigate = (section: string) => {
    setActiveSection(section);
    if (["spf", "dkim", "dmarc"].includes(section)) {
      setActiveAuthTab(section);
    }
  };

  const isAuthSection = ["spf", "dkim", "dmarc"].includes(activeSection);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex">
      <Toaster />
      
      {/* Left Sidebar Navigation */}
      <div className="w-80 flex-shrink-0 hidden lg:block">
        <div className="fixed w-80 h-screen">
          <Navigation activeSection={activeSection} onNavigate={handleNavigate} />
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 p-4 md:p-8 overflow-y-auto">
        <div className="max-w-4xl mx-auto">
          {/* Mobile Navigation */}
          <div className="lg:hidden mb-6">
            <select
              value={activeSection}
              onChange={(e) => handleNavigate(e.target.value)}
              className="w-full bg-white/10 backdrop-blur-xl border border-white/20 text-white rounded-lg p-3"
            >
              <option value="intro">Introduction</option>
              <option value="spf">SPF</option>
              <option value="dkim">DKIM</option>
              <option value="dmarc">DMARC</option>
              <option value="subdomains">Using Subdomains</option>
              <option value="mistakes">Common Mistakes</option>
              <option value="lookup">DNS Lookup Tool</option>
              <option value="lab">Practice Lab</option>
            </select>
          </div>

          {activeSection === "intro" && (
            <div className="space-y-8 pt-8">
              <div className="text-center mb-12">
                <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-500/20 backdrop-blur-xl border border-blue-400/30 rounded-full mb-4">
                  <Mail className="h-8 w-8 text-blue-300" />
                </div>
                <h1 className="text-white mb-3">Email Deliverability Course</h1>
                <p className="text-white/70 max-w-2xl mx-auto">
                  Master email authentication protocols to help customers ensure their messages reach the inbox. 
                  Learn SPF, DKIM, and DMARC configuration with hands-on practice.
                </p>
              </div>

              <CourseSection
                title="Email Authentication Overview"
                description="Understand the foundations of email deliverability and why authentication matters."
              >
                <ContentCard title="Why Email Authentication Matters">
                  <p>
                    Email authentication protocols protect domains from spoofing and phishing attacks 
                    while improving deliverability. Without proper authentication, legitimate emails 
                    may be rejected or marked as spam by receiving mail servers.
                  </p>
                </ContentCard>

                <ContentCard title="The Three Pillars">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-white/5 backdrop-blur-sm p-4 rounded-lg border border-white/10">
                      <Shield className="h-8 w-8 text-blue-400 mb-3" />
                      <h4 className="text-white mb-2">SPF</h4>
                      <p className="text-sm text-white/70">
                        Sender Policy Framework verifies which mail servers are authorized to send email 
                        on behalf of a domain.
                      </p>
                    </div>
                    <div className="bg-white/5 backdrop-blur-sm p-4 rounded-lg border border-white/10">
                      <CheckCircle className="h-8 w-8 text-blue-400 mb-3" />
                      <h4 className="text-white mb-2">DKIM</h4>
                      <p className="text-sm text-white/70">
                        DomainKeys Identified Mail adds a digital signature to emails to verify 
                        authenticity and prevent tampering.
                      </p>
                    </div>
                    <div className="bg-white/5 backdrop-blur-sm p-4 rounded-lg border border-white/10">
                      <Mail className="h-8 w-8 text-blue-400 mb-3" />
                      <h4 className="text-white mb-2">DMARC</h4>
                      <p className="text-sm text-white/70">
                        Domain-based Message Authentication tells receiving servers what to do when 
                        SPF or DKIM checks fail.
                      </p>
                    </div>
                  </div>
                </ContentCard>

                <ContentCard title="Course Structure">
                  <p className="mb-3">This training covers:</p>
                  <ul className="list-disc list-inside space-y-2 text-white/80">
                    <li>SPF, DKIM, and DMARC record configuration</li>
                    <li>Using subdomains for email sending</li>
                    <li>Common mistakes and troubleshooting techniques</li>
                    <li>DNS lookup tools for verification</li>
                    <li>Hands-on practice lab</li>
                  </ul>
                </ContentCard>
              </CourseSection>
            </div>
          )}

          {isAuthSection && (
            <div className="space-y-8 pt-8">
              <div>
                <h1 className="text-white mb-3">Learn Email Authentication</h1>
                <p className="text-white/70">
                  Configure and troubleshoot SPF, DKIM, and DMARC records for customer domains.
                </p>
              </div>

              <Tabs value={activeAuthTab} onValueChange={(value) => handleNavigate(value)} className="space-y-6">
                <TabsList className="bg-white/10 backdrop-blur-xl border border-white/20 p-1 w-full justify-start">
                  <TabsTrigger 
                    value="spf"
                    className="data-[state=active]:bg-white/20 data-[state=active]:text-white text-white/70"
                  >
                    SPF
                  </TabsTrigger>
                  <TabsTrigger 
                    value="dkim"
                    className="data-[state=active]:bg-white/20 data-[state=active]:text-white text-white/70"
                  >
                    DKIM
                  </TabsTrigger>
                  <TabsTrigger 
                    value="dmarc"
                    className="data-[state=active]:bg-white/20 data-[state=active]:text-white text-white/70"
                  >
                    DMARC
                  </TabsTrigger>
                </TabsList>

                <TabsContent value="spf">
                  <CourseSection
                    title="SPF (Sender Policy Framework)"
                    description="Configure SPF records to authorize mail servers to send email from a domain."
                  >
                    <ContentCard title="What is SPF?">
                      <p>
                        SPF is a DNS TXT record that lists all IP addresses and domains authorized to send 
                        email on behalf of a domain. When a receiving server gets an email, it checks 
                        the SPF record to verify the sender is legitimate.
                      </p>
                    </ContentCard>

                    <ContentCard title="SPF Record Structure">
                      <p>A basic SPF record follows this format:</p>
                      <CodeBlock>v=spf1 include:spfa.mailendo.com ~all</CodeBlock>
                      <ul className="list-disc list-inside space-y-2 mt-4">
                        <li><CodeBlock inline>v=spf1</CodeBlock> — Specifies SPF version 1</li>
                        <li><CodeBlock inline>include:spfa.mailendo.com</CodeBlock> — Authorizes Moosend's mail servers</li>
                        <li><CodeBlock inline>~all</CodeBlock> — Soft fail for unauthorized senders (recommended for testing)</li>
                        <li><CodeBlock inline>-all</CodeBlock> — Hard fail for unauthorized senders (use after testing)</li>
                      </ul>
                    </ContentCard>

                    <ContentCard title="Adding Moosend's SPF Record">
                      <p>
                        To authorize Moosend to send emails on behalf of a domain, add their SPF record to the 
                        DNS configuration:
                      </p>
                      <div className="mt-4 space-y-3">
                        <div>
                          <span className="text-white/60 text-sm">Record Type:</span>
                          <CodeBlock inline>TXT</CodeBlock>
                        </div>
                        <div>
                          <span className="text-white/60 text-sm">Host:</span>
                          <CodeBlock inline>@ (or leave blank for root domain)</CodeBlock>
                        </div>
                        <div>
                          <span className="text-white/60 text-sm">Value:</span>
                          <CodeBlock>v=spf1 include:spfa.mailendo.com ~all</CodeBlock>
                        </div>
                      </div>
                      <p className="mt-4">
                        If the customer already has an SPF record, add <CodeBlock inline>include:spfa.mailendo.com</CodeBlock> to 
                        the existing record instead of creating a new one.
                      </p>
                    </ContentCard>
                  </CourseSection>
                </TabsContent>

                <TabsContent value="dkim">
                  <CourseSection
                    title="DKIM (DomainKeys Identified Mail)"
                    description="Add cryptographic signatures to emails to verify authenticity."
                  >
                    <ContentCard title="What is DKIM?">
                      <p>
                        DKIM adds a digital signature to each email using public-key cryptography. 
                        The private key signs the email, and the public key (stored in DNS) verifies 
                        the signature hasn't been tampered with in transit.
                      </p>
                    </ContentCard>

                    <ContentCard title="DKIM Record Structure">
                      <p>
                        DKIM records are published as TXT records with a specific subdomain format:
                      </p>
                      <div className="mt-4 space-y-3">
                        <div>
                          <span className="text-white/60 text-sm">Record Type:</span>
                          <CodeBlock inline>TXT</CodeBlock>
                        </div>
                        <div>
                          <span className="text-white/60 text-sm">Host Format:</span>
                          <CodeBlock inline>selector._domainkey</CodeBlock>
                        </div>
                        <div>
                          <span className="text-white/60 text-sm">Example (Moosend):</span>
                          <CodeBlock inline>ms._domainkey</CodeBlock> or <CodeBlock inline>ms._domainkey.example.com</CodeBlock>
                        </div>
                        <div>
                          <span className="text-white/60 text-sm">Value:</span>
                          <CodeBlock>k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...</CodeBlock>
                        </div>
                      </div>
                    </ContentCard>

                    <ContentCard title="DNS Manager Host Value Requirements">
                      <p className="mb-4">
                        Different DNS managers handle the host value differently:
                      </p>
                      <div className="space-y-3">
                        <div className="bg-white/5 p-4 rounded-lg border border-white/10">
                          <p className="text-white mb-2">Some DNS managers require:</p>
                          <CodeBlock>Host: ms._domainkey</CodeBlock>
                          <p className="text-sm text-white/70 mt-2">
                            These managers automatically append the domain name.
                          </p>
                        </div>
                        <div className="bg-white/5 p-4 rounded-lg border border-white/10">
                          <p className="text-white mb-2">Other DNS managers require:</p>
                          <CodeBlock>Host: ms._domainkey.example.com</CodeBlock>
                          <p className="text-sm text-white/70 mt-2">
                            These managers require the full hostname including the domain.
                          </p>
                        </div>
                      </div>
                      <p className="mt-4 text-blue-300">
                        Both approaches are valid - it depends on the DNS manager being used.
                      </p>
                    </ContentCard>

                    <MistakeAlert 
                      type="warning" 
                      title="⚠️ TROUBLESHOOTING: DNS Manager Domain Duplication Issue"
                    >
                      <p className="mb-4">
                        <strong className="text-white">When to check for this issue:</strong> If the customer reports that 
                        their DKIM record isn't resolving and DNS lookups for <CodeBlock inline>ms._domainkey.example.com</CodeBlock> show 
                        no results (even after waiting for propagation), check for domain duplication.
                      </p>
                      
                      <p className="mb-3 text-white">The Problem:</p>
                      <p className="mb-4">
                        Some DNS managers auto-append the domain even when the customer enters the full hostname. 
                        If the customer enters <CodeBlock inline>ms._domainkey.example.com</CodeBlock> in a DNS manager 
                        that auto-appends, the actual DNS record will be created at <CodeBlock inline>ms._domainkey.example.com.example.com</CodeBlock>.
                      </p>

                      <p className="mb-3 text-white">How to Troubleshoot:</p>
                      <ol className="list-decimal list-inside space-y-2 mb-4">
                        <li>Customer adds DKIM record with host: <CodeBlock inline>ms._domainkey.example.com</CodeBlock></li>
                        <li>DNS lookup for <CodeBlock inline>ms._domainkey.example.com</CodeBlock> shows no results</li>
                        <li>Try looking up <CodeBlock inline>ms._domainkey.example.com.example.com</CodeBlock> instead</li>
                        <li>If the record appears at the duplicated location, the DNS manager auto-appended the domain</li>
                      </ol>

                      <p className="mb-2 text-white">Solution:</p>
                      <p>
                        Instruct the customer to use only <CodeBlock inline>ms._domainkey</CodeBlock> as the host value. 
                        Their DNS manager will automatically append <CodeBlock inline>.example.com</CodeBlock> to create the 
                        correct record at <CodeBlock inline>ms._domainkey.example.com</CodeBlock>.
                      </p>
                    </MistakeAlert>
                  </CourseSection>
                </TabsContent>

                <TabsContent value="dmarc">
                  <CourseSection
                    title="DMARC (Domain-based Message Authentication)"
                    description="Define policies for handling emails that fail SPF and DKIM checks."
                  >
                    <ContentCard title="What is DMARC?">
                      <p>
                        DMARC builds on SPF and DKIM by telling receiving mail servers what to do when 
                        authentication checks fail. It provides a policy framework for email authentication 
                        and helps protect domains from spoofing.
                      </p>
                    </ContentCard>

                    <ContentCard title="DMARC Record Structure">
                      <p>DMARC records are published as TXT records at the <CodeBlock inline>_dmarc</CodeBlock> subdomain:</p>
                      <div className="mt-4 space-y-3">
                        <div>
                          <span className="text-white/60 text-sm">Record Type:</span>
                          <CodeBlock inline>TXT</CodeBlock>
                        </div>
                        <div>
                          <span className="text-white/60 text-sm">Host:</span>
                          <CodeBlock inline>_dmarc</CodeBlock>
                        </div>
                        <div>
                          <span className="text-white/60 text-sm">Value:</span>
                          <CodeBlock>v=DMARC1; p=none;</CodeBlock>
                        </div>
                      </div>
                    </ContentCard>

                    <ContentCard title="DMARC Policies">
                      <p className="mb-4">The <CodeBlock inline>p=</CodeBlock> parameter defines what receiving servers should do with failed emails:</p>
                      <div className="space-y-3">
                        <div className="bg-white/5 p-4 rounded-lg border border-white/10">
                          <div className="flex items-start gap-3">
                            <CodeBlock inline>p=none</CodeBlock>
                            <div>
                              <p className="text-white mb-1">Monitor Only (Recommended Start)</p>
                              <p className="text-sm text-white/70">
                                No action taken on failed emails. Use this initially to monitor authentication 
                                without affecting delivery.
                              </p>
                            </div>
                          </div>
                        </div>
                        <div className="bg-white/5 p-4 rounded-lg border border-white/10">
                          <div className="flex items-start gap-3">
                            <CodeBlock inline>p=quarantine</CodeBlock>
                            <div>
                              <p className="text-white mb-1">Quarantine Failed Emails</p>
                              <p className="text-sm text-white/70">
                                Failed emails are sent to spam/junk folder. Use after monitoring shows 
                                good authentication results.
                              </p>
                            </div>
                          </div>
                        </div>
                        <div className="bg-white/5 p-4 rounded-lg border border-white/10">
                          <div className="flex items-start gap-3">
                            <CodeBlock inline>p=reject</CodeBlock>
                            <div>
                              <p className="text-white mb-1">Reject Failed Emails</p>
                              <p className="text-sm text-white/70">
                                Failed emails are rejected outright and not delivered. Use only when 
                                authentication is fully tested and working correctly.
                              </p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </ContentCard>

                    <MistakeAlert type="info" title="Implementation Guidance">
                      <p>
                        Always recommend customers start with <CodeBlock inline>p=none</CodeBlock> to monitor 
                        authentication results before enforcing stricter policies. This prevents legitimate 
                        emails from being blocked due to misconfiguration.
                      </p>
                    </MistakeAlert>
                  </CourseSection>
                </TabsContent>
              </Tabs>
            </div>
          )}

          {activeSection === "subdomains" && (
            <div className="space-y-8 pt-8">
              <CourseSection
                title="Using Subdomains for Email Sending"
                description="Configure email authentication on subdomains to isolate email reputation."
              >
                <ContentCard title="Why Use Subdomains?">
                  <p className="mb-4">
                    Sending email from a subdomain (like <CodeBlock inline>mail.example.com</CodeBlock> or <CodeBlock inline>newsletter.example.com</CodeBlock>) 
                    protects the primary domain's reputation.
                  </p>
                  <p className="mb-3">Benefits:</p>
                  <ul className="list-disc list-inside space-y-2 text-white/80">
                    <li>If marketing emails get marked as spam, it won't affect transactional emails from the main domain</li>
                    <li>Separate reputation management for different email types</li>
                    <li>Easier to isolate and troubleshoot deliverability issues</li>
                    <li>Can apply different authentication policies per subdomain</li>
                  </ul>
                </ContentCard>

                <ContentCard title="Subdomain Email Authentication Setup">
                  <p className="mb-4">
                    To configure email authentication for a subdomain, you'll add DNS records for SPF, DKIM, and DMARC 
                    specifically for that subdomain.
                  </p>
                  
                  <div className="space-y-6">
                    <div>
                      <p className="text-white mb-3">Example: Setting up authentication for <CodeBlock inline>mail.example.com</CodeBlock></p>
                      
                      <div className="space-y-4 mt-4">
                        <div className="bg-white/5 p-4 rounded-lg border border-white/10">
                          <p className="text-white mb-2">SPF Record:</p>
                          <div className="space-y-2">
                            <div>
                              <span className="text-white/60 text-sm">Host:</span>
                              <CodeBlock inline>mail</CodeBlock>
                            </div>
                            <div>
                              <span className="text-white/60 text-sm">Value:</span>
                              <CodeBlock inline>v=spf1 include:spfa.mailendo.com ~all</CodeBlock>
                            </div>
                          </div>
                        </div>

                        <div className="bg-white/5 p-4 rounded-lg border border-white/10">
                          <p className="text-white mb-2">DKIM Record:</p>
                          <div className="space-y-2">
                            <div>
                              <span className="text-white/60 text-sm">Host:</span>
                              <CodeBlock inline>ms._domainkey.mail</CodeBlock> or <CodeBlock inline>ms._domainkey.mail.example.com</CodeBlock>
                            </div>
                            <div>
                              <span className="text-white/60 text-sm">Value:</span>
                              <CodeBlock inline>k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...</CodeBlock>
                            </div>
                            <p className="text-sm text-white/70 mt-2">
                              (Depends on DNS manager - see DKIM section for details)
                            </p>
                          </div>
                        </div>

                        <div className="bg-white/5 p-4 rounded-lg border border-white/10">
                          <p className="text-white mb-2">DMARC Record:</p>
                          <div className="space-y-2">
                            <div>
                              <span className="text-white/60 text-sm">Host:</span>
                              <CodeBlock inline>_dmarc.mail</CodeBlock>
                            </div>
                            <div>
                              <span className="text-white/60 text-sm">Value:</span>
                              <CodeBlock inline>v=DMARC1; p=none;</CodeBlock>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </ContentCard>

                <ContentCard title="Common Subdomain Strategies">
                  <div className="space-y-3">
                    <div className="bg-white/5 p-4 rounded-lg border border-white/10">
                      <p className="text-white mb-2"><CodeBlock inline>marketing.example.com</CodeBlock></p>
                      <p className="text-sm text-white/70">Use for promotional campaigns and newsletters</p>
                    </div>
                    <div className="bg-white/5 p-4 rounded-lg border border-white/10">
                      <p className="text-white mb-2"><CodeBlock inline>transactional.example.com</CodeBlock></p>
                      <p className="text-sm text-white/70">Use for order confirmations, receipts, and account emails</p>
                    </div>
                    <div className="bg-white/5 p-4 rounded-lg border border-white/10">
                      <p className="text-white mb-2"><CodeBlock inline>notifications.example.com</CodeBlock></p>
                      <p className="text-sm text-white/70">Use for system alerts and automated notifications</p>
                    </div>
                  </div>
                </ContentCard>

                <MistakeAlert type="info" title="Subdomain Best Practice">
                  <p>
                    Each subdomain needs its own complete set of email authentication records (SPF, DKIM, DMARC). 
                    The records on the root domain do not automatically apply to subdomains.
                  </p>
                </MistakeAlert>
              </CourseSection>
            </div>
          )}

          {activeSection === "mistakes" && (
            <div className="space-y-8 pt-8">
              <div className="mb-8">
                <div className="inline-flex items-center justify-center w-16 h-16 bg-amber-500/20 backdrop-blur-xl border border-amber-400/30 rounded-full mb-4">
                  <AlertTriangle className="h-8 w-8 text-amber-300" />
                </div>
                <h1 className="text-white mb-3">Common Mistakes & Troubleshooting</h1>
                <p className="text-white/70">
                  Reference guide for diagnosing and resolving the most common email authentication issues.
                </p>
              </div>

              <CourseSection
                title="SPF Issues"
                description="Common SPF configuration mistakes and how to fix them."
              >
                <MistakeAlert 
                  type="warning" 
                  title="⚠️ Multiple SPF Records"
                >
                  <p className="mb-3">
                    <strong className="text-white">Symptom:</strong> Emails are being rejected or marked as spam despite having SPF configured.
                  </p>
                  <p className="mb-3">
                    <strong className="text-white">Cause:</strong> Customer has created two or more separate SPF TXT records on the same domain/subdomain. 
                    This happens when they add email service providers over time without combining them.
                  </p>
                  <p className="mb-2 text-white">How to diagnose:</p>
                  <p className="mb-3">Use DNS Lookup Tool to search for TXT records on the domain. If you see multiple records starting with <CodeBlock inline>v=spf1</CodeBlock>, this invalidates SPF.</p>
                  
                  <p className="mb-2 text-white">❌ INCORRECT Example (Three separate SPF records):</p>
                  <div className="space-y-2 mb-3 bg-black/30 p-4 rounded-lg">
                    <CodeBlock>v=spf1 include:_spf.google.com ~all</CodeBlock>
                    <CodeBlock>v=spf1 include:spfa.mailendo.com ~all</CodeBlock>
                    <CodeBlock>v=spf1 include:spf.protection.outlook.com ~all</CodeBlock>
                  </div>
                  <p className="text-sm text-white/70 mb-4">
                    Having three separate SPF records invalidates all of them. Email authentication will fail.
                  </p>

                  <p className="mb-2 text-white">✅ CORRECT Solution (Combined into one record):</p>
                  <CodeBlock>v=spf1 include:_spf.google.com include:spfa.mailendo.com include:spf.protection.outlook.com ~all</CodeBlock>
                  <p className="text-sm text-white/70 mt-3">
                    All email service providers must be included in a single SPF record, separated by spaces.
                  </p>
                </MistakeAlert>

                <MistakeAlert 
                  type="warning" 
                  title="⚠️ SPF Record Too Long (10 DNS Lookup Limit)"
                >
                  <p className="mb-3">
                    <strong className="text-white">Symptom:</strong> SPF validation fails with "permerror" or "too many DNS lookups".
                  </p>
                  <p className="mb-3">
                    <strong className="text-white">Cause:</strong> SPF has a limit of 10 DNS lookups. Each <CodeBlock inline>include:</CodeBlock>, <CodeBlock inline>a</CodeBlock>, <CodeBlock inline>mx</CodeBlock>, <CodeBlock inline>ptr</CodeBlock>, 
                    and <CodeBlock inline>exists</CodeBlock> mechanism counts as a lookup. <strong className="text-white">Critically, each include can trigger additional lookups</strong> - 
                    you can't just count the includes in your record.
                  </p>
                  
                  <p className="mb-2 text-white">Example of the Hidden Lookup Problem:</p>
                  <div className="bg-black/30 p-4 rounded-lg mb-4">
                    <CodeBlock>v=spf1 include:websitewelcome.com ~all</CodeBlock>
                    <p className="text-sm text-white/70 mt-3">
                      This looks like just 1 lookup, but <CodeBlock inline>include:websitewelcome.com</CodeBlock> internally uses 7 DNS lookups:
                    </p>
                    <ul className="text-sm text-white/70 mt-2 ml-4 space-y-1">
                      <li>• Lookup 1: websitewelcome.com</li>
                      <li>• Lookup 2: _spf.google.com (nested)</li>
                      <li>• Lookup 3: _netblocks.google.com (nested)</li>
                      <li>• Lookup 4: _netblocks2.google.com (nested)</li>
                      <li>• Lookup 5: _netblocks3.google.com (nested)</li>
                      <li>• Lookup 6: spf.mandrillapp.com (nested)</li>
                      <li>• Lookup 7: spf.mtasv.net (nested)</li>
                    </ul>
                  </div>

                  <p className="mb-2 text-white">How to diagnose:</p>
                  <p className="mb-3">
                    You cannot easily count lookups manually. Use an SPF record checker tool (search "SPF record checker" online) 
                    that shows the total DNS lookup count. If it shows 10 or more lookups, you've hit the limit.
                  </p>
                  
                  <p className="mb-2 text-white">Solution:</p>
                  <ul className="list-disc list-inside space-y-2">
                    <li>Remove unnecessary email service providers from the SPF record</li>
                    <li>Replace some includes with direct IP addresses using <CodeBlock inline>ip4:</CodeBlock> or <CodeBlock inline>ip6:</CodeBlock> (doesn't use lookups)</li>
                    <li>Consider using subdomains to split email sending across different domains</li>
                    <li>Contact email service providers to get their IP ranges for direct inclusion</li>
                  </ul>
                </MistakeAlert>

                <MistakeAlert 
                  type="warning" 
                  title="⚠️ Missing SPF Record"
                >
                  <p className="mb-3">
                    <strong className="text-white">Symptom:</strong> Emails are being rejected with "SPF fail" or "no SPF record found".
                  </p>
                  <p className="mb-3">
                    <strong className="text-white">Cause:</strong> No SPF record exists on the domain or subdomain being used to send email.
                  </p>
                  <p className="mb-2 text-white">How to diagnose:</p>
                  <p className="mb-3">Use DNS Lookup Tool to search for TXT records. If no record starts with <CodeBlock inline>v=spf1</CodeBlock>, SPF is not configured.</p>
                  <p className="mb-2 text-white">Solution:</p>
                  <p>Add an SPF record to the domain/subdomain used for sending.</p>
                </MistakeAlert>
              </CourseSection>

              <CourseSection
                title="DKIM Issues"
                description="Common DKIM configuration mistakes and how to fix them."
              >
                <MistakeAlert 
                  type="warning" 
                  title="⚠️ DNS Manager Domain Duplication"
                >
                  <p className="mb-3">
                    <strong className="text-white">Symptom:</strong> DKIM record appears to be added but DNS lookups show no record found. 
                    May show "waiting for DNS propagation" for extended periods (24+ hours).
                  </p>
                  <p className="mb-3">
                    <strong className="text-white">Cause:</strong> DNS manager auto-appended the domain to the host value, creating a record 
                    at <CodeBlock inline>ms._domainkey.example.com.example.com</CodeBlock> instead of <CodeBlock inline>ms._domainkey.example.com</CodeBlock>.
                  </p>
                  <p className="mb-2 text-white">How to diagnose:</p>
                  <ol className="list-decimal list-inside space-y-2 mb-3">
                    <li>DNS lookup for <CodeBlock inline>ms._domainkey.example.com</CodeBlock> shows no results</li>
                    <li>Check if customer entered <CodeBlock inline>ms._domainkey.example.com</CodeBlock> as the host value</li>
                    <li>Try looking up <CodeBlock inline>ms._domainkey.example.com.example.com</CodeBlock></li>
                    <li>If record appears at the duplicated location, domain was auto-appended</li>
                  </ol>
                  <p className="mb-2 text-white">Solution:</p>
                  <p className="mb-2">Delete the incorrect record and recreate using only <CodeBlock inline>ms._domainkey</CodeBlock> as the host value.</p>
                  <p className="text-sm text-white/70">The DNS manager will automatically append the domain.</p>
                </MistakeAlert>

                <MistakeAlert 
                  type="warning" 
                  title="⚠️ Missing Semicolons in DKIM Value"
                >
                  <p className="mb-3">
                    <strong className="text-white">Symptom:</strong> DKIM validation fails even though the record exists.
                  </p>
                  <p className="mb-3">
                    <strong className="text-white">Cause:</strong> DKIM record value is missing required semicolons between parameters.
                  </p>
                  <p className="mb-2 text-white">Incorrect:</p>
                  <CodeBlock>k=rsa p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...</CodeBlock>
                  <p className="mb-2 mt-3 text-white">Correct:</p>
                  <CodeBlock>k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...</CodeBlock>
                  <p className="mt-3">Note the semicolon after <CodeBlock inline>k=rsa</CodeBlock></p>
                </MistakeAlert>

                <MistakeAlert 
                  type="warning" 
                  title="⚠️ Spaces or Line Breaks in DKIM Value"
                >
                  <p className="mb-3">
                    <strong className="text-white">Symptom:</strong> DKIM validation fails or shows "syntax error".
                  </p>
                  <p className="mb-3">
                    <strong className="text-white">Cause:</strong> Customer accidentally added spaces or line breaks when copying the DKIM public key.
                  </p>
                  <p className="mb-2 text-white">Solution:</p>
                  <p>Ensure the entire DKIM value is on a single line with no extra spaces. Some DNS managers support multi-line, but it's safer to use a single line.</p>
                </MistakeAlert>
              </CourseSection>

              <CourseSection
                title="DMARC Issues"
                description="Common DMARC configuration mistakes and how to fix them."
              >
                <MistakeAlert 
                  type="warning" 
                  title="⚠️ DMARC Policy Too Strict Without Testing"
                >
                  <p className="mb-3">
                    <strong className="text-white">Symptom:</strong> Legitimate emails are being quarantined or rejected after implementing DMARC.
                  </p>
                  <p className="mb-3">
                    <strong className="text-white">Cause:</strong> Customer set <CodeBlock inline>p=quarantine</CodeBlock> or <CodeBlock inline>p=reject</CodeBlock> without 
                    first monitoring with <CodeBlock inline>p=none</CodeBlock>.
                  </p>
                  <p className="mb-2 text-white">Solution:</p>
                  <ol className="list-decimal list-inside space-y-2">
                    <li>Change policy to <CodeBlock inline>p=none</CodeBlock> immediately to restore delivery</li>
                    <li>Ensure SPF and DKIM are properly configured and passing</li>
                    <li>Monitor for several weeks before increasing policy strictness</li>
                  </ol>
                </MistakeAlert>

                <MistakeAlert 
                  type="warning" 
                  title="⚠️ Missing Semicolons in DMARC Value"
                >
                  <p className="mb-3">
                    <strong className="text-white">Symptom:</strong> DMARC record exists but is not being honored by receiving servers.
                  </p>
                  <p className="mb-3">
                    <strong className="text-white">Cause:</strong> DMARC parameters must be separated by semicolons.
                  </p>
                  <p className="mb-2 text-white">Incorrect:</p>
                  <CodeBlock>v=DMARC1 p=none</CodeBlock>
                  <p className="mb-2 mt-3 text-white">Correct:</p>
                  <CodeBlock>v=DMARC1; p=none;</CodeBlock>
                </MistakeAlert>
              </CourseSection>

              <CourseSection
                title="General Troubleshooting"
                description="Issues that apply across all record types."
              >
                <MistakeAlert 
                  type="warning" 
                  title="⚠️ DNS Propagation Expectations"
                >
                  <p className="mb-3">
                    <strong className="text-white">Symptom:</strong> Customer reports records aren't working "yet" or asks "how long until it works?"
                  </p>
                  <p className="mb-3">
                    <strong className="text-white">Reality:</strong> DNS propagation is usually much faster than customers expect.
                  </p>
                  <div className="space-y-2 my-3">
                    <div className="flex items-center gap-3">
                      <Clock className="h-5 w-5 text-blue-400" />
                      <span>Typical propagation: 5-30 minutes</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <Clock className="h-5 w-5 text-blue-400" />
                      <span>Maximum propagation: 24-48 hours (rare)</span>
                    </div>
                  </div>
                  <p className="mb-2 text-white">Troubleshooting tip:</p>
                  <p>
                    If a record doesn't appear after 30 minutes, it's more likely a configuration error than propagation delay. 
                    Use the DNS Lookup Tool to check if the record exists (or exists in the wrong place).
                  </p>
                </MistakeAlert>

                <MistakeAlert 
                  type="warning" 
                  title="⚠️ Wrong Record Type"
                >
                  <p className="mb-3">
                    <strong className="text-white">Symptom:</strong> Record appears to be configured but doesn't validate.
                  </p>
                  <p className="mb-3">
                    <strong className="text-white">Cause:</strong> Customer created the record with the wrong type (e.g., CNAME instead of TXT).
                  </p>
                  <p className="mb-2 text-white">Solution:</p>
                  <p className="mb-3">All email authentication records (SPF, DKIM, DMARC) must be TXT records. Delete the incorrect record and recreate as TXT.</p>
                </MistakeAlert>

                <MistakeAlert 
                  type="warning" 
                  title="⚠️ Quotes Around Record Values"
                >
                  <p className="mb-3">
                    <strong className="text-white">Symptom:</strong> Record appears correct but validation fails.
                  </p>
                  <p className="mb-3">
                    <strong className="text-white">Cause:</strong> Some DNS managers require quotes around TXT record values, others don't.
                  </p>
                  <p className="mb-2 text-white">General rule:</p>
                  <ul className="list-disc list-inside space-y-2">
                    <li>If the DNS manager interface shows a text input field, typically no quotes needed</li>
                    <li>If unsure, try both with and without quotes</li>
                    <li>Use DNS Lookup Tool to see what was actually published</li>
                  </ul>
                </MistakeAlert>

                <MistakeAlert 
                  type="info" 
                  title="Systematic Troubleshooting Approach"
                >
                  <p className="mb-3 text-white">When a customer reports email authentication issues:</p>
                  <ol className="list-decimal list-inside space-y-2">
                    <li>Ask for their domain name and which subdomain they're using (if any)</li>
                    <li>Use DNS Lookup Tool to check what records actually exist</li>
                    <li>Check for common issues: multiple SPF records, domain duplication, wrong record type</li>
                    <li>If record doesn't exist where expected, check the duplicated location (e.g., <CodeBlock inline>example.com.example.com</CodeBlock>)</li>
                    <li>Verify record syntax: semicolons, no extra spaces, correct format</li>
                    <li>If recently added, wait 30 minutes and check again</li>
                    <li>Have customer send a test email and check email headers for authentication results</li>
                  </ol>
                </MistakeAlert>
              </CourseSection>
            </div>
          )}

          {activeSection === "lookup" && (
            <div className="pt-8">
              <DNSLookup />
            </div>
          )}

          {activeSection === "lab" && (
            <div className="pt-8">
              <DNSLab />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
