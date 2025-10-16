import { useState } from "react";
import { Card } from "./ui/card";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Button } from "./ui/button";
import { Alert, AlertDescription } from "./ui/alert";
import { CheckCircle2, XCircle, Plus, Trash2 } from "lucide-react";

interface DNSRecord {
  id: string;
  type: string;
  host: string;
  value: string;
}

export function DNSLab() {
  const [records, setRecords] = useState<DNSRecord[]>([
    {
      id: "1",
      type: "TXT",
      host: "@",
      value: "",
    },
  ]);
  
  const [validation, setValidation] = useState<{
    show: boolean;
    type: "success" | "error";
    messages: string[];
  }>({ show: false, type: "success", messages: [] });

  const addRecord = () => {
    setRecords([
      ...records,
      {
        id: Date.now().toString(),
        type: "TXT",
        host: "@",
        value: "",
      },
    ]);
  };

  const removeRecord = (id: string) => {
    setRecords(records.filter((record) => record.id !== id));
  };

  const updateRecord = (id: string, field: keyof DNSRecord, value: string) => {
    setRecords(
      records.map((record) =>
        record.id === id ? { ...record, [field]: value } : record
      )
    );
  };

  const validateRecords = () => {
    const errors: string[] = [];
    const successes: string[] = [];
    
    // Check for multiple SPF records
    const spfRecords = records.filter(
      (r) => r.host === "@" && r.value.startsWith("v=spf1")
    );
    
    if (spfRecords.length > 1) {
      errors.push("Multiple SPF records detected on root domain. Only one SPF record is allowed per domain. Combine them into a single record.");
    } else if (spfRecords.length === 1) {
      successes.push("SPF record structure is valid.");
      
      // Check if it includes moosend
      if (spfRecords[0].value.includes("include:spfa.mailendo.com")) {
        successes.push("Moosend SPF record correctly included.");
      }
    }
    
    // Check for DKIM domain duplication
    const dkimRecords = records.filter((r) => r.host.includes("._domainkey"));
    dkimRecords.forEach((record) => {
      if (record.host.match(/\._domainkey\..*\./)) {
        errors.push(`DKIM record "${record.host}" appears to have a duplicated domain. Check if your DNS manager auto-appends the domain.`);
      } else {
        successes.push(`DKIM record "${record.host}" is formatted correctly.`);
      }
    });
    
    // Check for empty values
    const emptyRecords = records.filter((r) => !r.value.trim());
    if (emptyRecords.length > 0) {
      errors.push("Some records have empty values. All records must have a value.");
    }
    
    setValidation({
      show: true,
      type: errors.length > 0 ? "error" : "success",
      messages: errors.length > 0 ? errors : successes,
    });
  };

  const loadExample = (example: "spf" | "dkim" | "dmarc" | "subdomain") => {
    switch (example) {
      case "spf":
        setRecords([
          {
            id: "1",
            type: "TXT",
            host: "@",
            value: "v=spf1 include:spfa.mailendo.com ~all",
          },
        ]);
        break;
      case "dkim":
        setRecords([
          {
            id: "1",
            type: "TXT",
            host: "ms._domainkey",
            value: "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...",
          },
        ]);
        break;
      case "dmarc":
        setRecords([
          {
            id: "1",
            type: "TXT",
            host: "_dmarc",
            value: "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
          },
        ]);
        break;
      case "subdomain":
        setRecords([
          {
            id: "1",
            type: "TXT",
            host: "mail",
            value: "v=spf1 include:spfa.mailendo.com ~all",
          },
          {
            id: "2",
            type: "TXT",
            host: "ms._domainkey.mail",
            value: "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...",
          },
        ]);
        break;
    }
    setValidation({ show: false, type: "success", messages: [] });
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-white mb-2">DNS Manager Lab</h2>
        <p className="text-white/70">
          Practice adding and validating DNS records. Try different scenarios to test your understanding.
        </p>
      </div>

      <Card className="bg-white/10 backdrop-blur-xl border-white/20 p-6">
        <div className="space-y-6">
          <div className="flex gap-2 flex-wrap">
            <Button
              onClick={() => loadExample("spf")}
              variant="outline"
              size="sm"
              className="bg-white/5 border-white/20 text-white hover:bg-white/10"
            >
              Load SPF Example
            </Button>
            <Button
              onClick={() => loadExample("dkim")}
              variant="outline"
              size="sm"
              className="bg-white/5 border-white/20 text-white hover:bg-white/10"
            >
              Load DKIM Example
            </Button>
            <Button
              onClick={() => loadExample("dmarc")}
              variant="outline"
              size="sm"
              className="bg-white/5 border-white/20 text-white hover:bg-white/10"
            >
              Load DMARC Example
            </Button>
            <Button
              onClick={() => loadExample("subdomain")}
              variant="outline"
              size="sm"
              className="bg-white/5 border-white/20 text-white hover:bg-white/10"
            >
              Load Subdomain Example
            </Button>
          </div>

          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <Label className="text-white">DNS Records</Label>
              <Button
                onClick={addRecord}
                size="sm"
                className="bg-blue-500/20 border border-blue-400/30 text-blue-300 hover:bg-blue-500/30"
              >
                <Plus className="h-4 w-4 mr-2" />
                Add Record
              </Button>
            </div>

            {records.map((record, index) => (
              <Card
                key={record.id}
                className="bg-white/5 backdrop-blur-sm border-white/10 p-4"
              >
                <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
                  <div className="md:col-span-2">
                    <Label className="text-white/80 text-sm mb-2 block">Type</Label>
                    <Input
                      value={record.type}
                      onChange={(e) => updateRecord(record.id, "type", e.target.value)}
                      className="bg-white/10 border-white/20 text-white placeholder:text-white/40"
                      placeholder="TXT"
                    />
                  </div>
                  <div className="md:col-span-3">
                    <Label className="text-white/80 text-sm mb-2 block">Host</Label>
                    <Input
                      value={record.host}
                      onChange={(e) => updateRecord(record.id, "host", e.target.value)}
                      className="bg-white/10 border-white/20 text-white placeholder:text-white/40"
                      placeholder="@"
                    />
                  </div>
                  <div className="md:col-span-6">
                    <Label className="text-white/80 text-sm mb-2 block">Value</Label>
                    <Input
                      value={record.value}
                      onChange={(e) => updateRecord(record.id, "value", e.target.value)}
                      className="bg-white/10 border-white/20 text-white placeholder:text-white/40"
                      placeholder="Enter DNS record value"
                    />
                  </div>
                  <div className="md:col-span-1 flex justify-end">
                    {records.length > 1 && (
                      <Button
                        onClick={() => removeRecord(record.id)}
                        variant="ghost"
                        size="sm"
                        className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                </div>
              </Card>
            ))}
          </div>

          <Button
            onClick={validateRecords}
            className="w-full bg-blue-500/30 border border-blue-400/50 text-white hover:bg-blue-500/40"
          >
            Validate Configuration
          </Button>

          {validation.show && (
            <Alert
              className={
                validation.type === "error"
                  ? "bg-red-500/10 backdrop-blur-xl border-red-500/30"
                  : "bg-green-500/10 backdrop-blur-xl border-green-500/30"
              }
            >
              {validation.type === "error" ? (
                <XCircle className="h-5 w-5 text-red-400" />
              ) : (
                <CheckCircle2 className="h-5 w-5 text-green-400" />
              )}
              <AlertDescription className="text-white/90">
                <span className="block mb-2">
                  {validation.type === "error" ? "Issues Detected:" : "Validation Passed:"}
                </span>
                <ul className="list-disc list-inside space-y-1">
                  {validation.messages.map((message, i) => (
                    <li key={i}>{message}</li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          )}
        </div>
      </Card>
    </div>
  );
}
